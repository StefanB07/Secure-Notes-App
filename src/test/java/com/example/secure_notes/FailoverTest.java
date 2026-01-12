package com.example.secure_notes;

import com.example.secure_notes.config.FailoverDataSourceConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("docker") // Forces the use of your Failover Config
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD) // Resets the context after we break things
public class FailoverTest {

    @Autowired
    private FailoverDataSourceConfig failoverConfig;

    @Autowired
    private DataSource dataSource;

    @Test
    @DisplayName("Failover Logic: Switch to Replica when Master fails")
    public void testFailoverLogic() throws Exception {
        // 1. Access the private fields using Reflection (needed to simulate internal state)
        Field masterPoolField = FailoverDataSourceConfig.class.getDeclaredField("masterPool");
        masterPoolField.setAccessible(true);
        HikariDataSource masterPool = (HikariDataSource) masterPoolField.get(failoverConfig);

        Field currentDataSourceField = FailoverDataSourceConfig.class.getDeclaredField("currentDataSource");
        currentDataSourceField.setAccessible(true);
        AtomicReference<HikariDataSource> currentDataSource = (AtomicReference<HikariDataSource>) currentDataSourceField.get(failoverConfig);

        // 2. INITIAL STATE: Assert we are connected to Master
        assertNotNull(masterPool, "Master pool should be initialized");
        assertEquals(masterPool, currentDataSource.get(), "Should start connected to Master");
        assertTrue(isConnectionValid(dataSource), "Master connection should be valid initially");

        // 3. SIMULATE FAILURE: Force close the Master Pool
        System.out.println("TEST: Simulating Master Crash...");
        masterPool.close(); // This kills the connection pool

        // 4. TRIGGER FAILOVER: Manually invoke the health check method
        Method checkHealthMethod = FailoverDataSourceConfig.class.getDeclaredMethod("checkHealthAndFailover");
        checkHealthMethod.setAccessible(true);
        checkHealthMethod.invoke(failoverConfig); // Run the logic immediately

        // 5. ASSERT FAILOVER: Verify we switched to Replica
        HikariDataSource activePoolAfterFailover = currentDataSource.get();
        assertNotEquals(masterPool, activePoolAfterFailover, "Should have switched AWAY from Master");
        assertEquals("Hikari-replica", activePoolAfterFailover.getPoolName(), "Should have switched TO Replica");

        // 6. VERIFY AVAILABILITY: App should still be able to get connections (Read-Only)
        assertTrue(isConnectionValid(dataSource), "Application should still have a valid connection (via Replica)");
    }

    // Helper method to check if the datasource is alive
    private boolean isConnectionValid(DataSource ds) {
        try (Connection conn = ds.getConnection()) {
            return conn.isValid(1);
        } catch (SQLException e) {
            return false;
        }
    }
}