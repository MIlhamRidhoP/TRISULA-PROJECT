/*
 * Hand-written fixture helper for TRISULA tests.
 */
package org.owasp.benchmark.helpers;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletResponse;

public class DatabaseHelper {

    public static boolean hideSQLErrors = false;

    public static Connection getSqlConnection() throws SQLException {
        return java.sql.DriverManager.getConnection("jdbc:hsqldb:mem:fixture", "sa", "");
    }

    public static Statement getSqlStatement() throws SQLException {
        return getSqlConnection().createStatement();
    }

    public static void printResults(Statement statement, String sql, HttpServletResponse response)
            throws SQLException, java.io.IOException {
        response.getWriter().println("Executed: " + sql);
    }

    public static void printResults(ResultSet rs, String sql, HttpServletResponse response)
            throws SQLException, java.io.IOException {
        response.getWriter().println("Rows for: " + sql);
    }

    public static void printResults(
            PreparedStatement statement, String sql, HttpServletResponse response)
            throws SQLException, java.io.IOException {
        response.getWriter().println("Executed: " + sql);
    }
}
