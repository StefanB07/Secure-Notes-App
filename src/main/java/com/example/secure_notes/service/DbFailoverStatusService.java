package com.example.secure_notes.service;

import javax.sql.DataSource;
import java.sql.Connection;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Detects whether the application is currently operating in database failover mode.
 * The failover mode is defined as: master DB is not reachable, but a DB connection
 * is still possible (typically the replica).
 */
@Service
public class DbFailoverStatusService {

    private final DataSource dataSource;
    private final String masterJdbcUrl;

    public DbFailoverStatusService(DataSource dataSource,
                                   @Value("${spring.datasource.master.url:}") String masterJdbcUrl) {
        this.dataSource = dataSource;
        this.masterJdbcUrl = masterJdbcUrl;
    }

    public boolean isFailoverMode() {
        // If master URL isn't configured, we can't make a strong statement.
        if (masterJdbcUrl == null || masterJdbcUrl.isBlank()) {
            return false;
        }

        try (Connection c = dataSource.getConnection()) {
            String currentUrl = c.getMetaData().getURL();
            // If we can connect and current URL isn't master, we assume we're on replica.
            return currentUrl != null && !currentUrl.equals(masterJdbcUrl);
        } catch (Exception ignored) {
            return false;
        }
    }
}

