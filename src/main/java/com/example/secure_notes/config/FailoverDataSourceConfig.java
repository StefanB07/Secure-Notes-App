package com.example.secure_notes.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.datasource.AbstractDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@Profile("docker")
@Configuration
public class FailoverDataSourceConfig implements DisposableBean {

    @Value("${spring.datasource.master.url}")
    private String masterUrl;

    @Value("${spring.datasource.master.username}")
    private String masterUser;

    @Value("${spring.datasource.master.password}")
    private String masterPass;

    @Value("${spring.datasource.replica.url}")
    private String replicaUrl;

    @Value("${spring.datasource.replica.username}")
    private String replicaUser;

    @Value("${spring.datasource.replica.password}")
    private String replicaPass;

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "db-failover-healthcheck");
        t.setDaemon(true);
        return t;
    });

    // Holds the currently active DataSource (Master or Replica)
    private final AtomicReference<HikariDataSource> currentDataSource = new AtomicReference<>();

    private HikariDataSource masterPool;
    private HikariDataSource replicaPool;

    @Bean
    @Primary
    public DataSource dataSource() {
        // 1. Create Connection Pools
        masterPool = createPool(masterUrl, masterUser, masterPass, "master");
        replicaPool = createPool(replicaUrl, replicaUser, replicaPass, "replica");

        // 2. Initial State: Try Master, fallback to Replica
        if (isNodeHealthy(masterPool)) {
            currentDataSource.set(masterPool);
            System.out.println(">>> INITIALIZED: Connected to MASTER DB");
        } else {
            currentDataSource.set(replicaPool);
            System.out.println(">>> INITIALIZED: Connected to REPLICA DB (Read-Only Mode)");
        }

        // 3. Start Background Health Check (Every 5 seconds)
        scheduler.scheduleAtFixedRate(this::checkHealthAndFailover, 5, 5, TimeUnit.SECONDS);

        // 4. Return a wrapper that delegates to the active pool
        return new RoutingDataSource(currentDataSource);
    }

    private void checkHealthAndFailover() {
        boolean masterUp = isNodeHealthy(masterPool);
        HikariDataSource active = currentDataSource.get();

        // SCENARIO 1: Master died, currently on Master -> Switch to Replica
        if (!masterUp && active == masterPool) {
            System.err.println("!!! ALERT: MASTER DB DOWN. Switching to REPLICA.");
            currentDataSource.set(replicaPool);
        }

        // SCENARIO 2: Master is back, currently on Replica -> Switch back to Master
        if (masterUp && active == replicaPool) {
            System.out.println(">>> INFO: MASTER DB RECOVERED. Switching back to MASTER.");
            currentDataSource.set(masterPool);
        }
    }

    private boolean isNodeHealthy(HikariDataSource ds) {
        if (ds == null || ds.isClosed()) return false;
        try (Connection conn = ds.getConnection()) {
            // Check if connection is valid with 1 second timeout
            return conn.isValid(1);
        } catch (SQLException e) {
            return false;
        }
    }

    private HikariDataSource createPool(String url, String user, String pass, String name) {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl(url);
        ds.setUsername(user);
        ds.setPassword(pass);
        ds.setPoolName("Hikari-" + name);
        ds.setMaximumPoolSize(10);
        ds.setConnectionTimeout(2000); // Fast failover (2s)
        ds.setValidationTimeout(1000);
        return ds;
    }

    @Override
    public void destroy() {
        scheduler.shutdownNow();
        if (masterPool != null) masterPool.close();
        if (replicaPool != null) replicaPool.close();
    }

    /**
     * A lightweight wrapper that redirects calls to the currently active AtomicReference pool.
     */
    static class RoutingDataSource extends AbstractDataSource {
        private final AtomicReference<HikariDataSource> dataSourceRef;

        public RoutingDataSource(AtomicReference<HikariDataSource> dataSourceRef) {
            this.dataSourceRef = dataSourceRef;
        }

        @Override
        public Connection getConnection() throws SQLException {
            return dataSourceRef.get().getConnection();
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return dataSourceRef.get().getConnection(username, password);
        }
    }
}