/**
 * Hand-written fixture for TRISULA tests. Shaped like an OWASP Benchmark test case, but not
 * taken from it.
 *
 * @author fixture
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/sqli-00/BenchmarkTest00007")
public class BenchmarkTest00007 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00007") != null) {
            param = request.getHeader("BenchmarkTest00007"); // header value is not decoded
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String sql = "SELECT * FROM USERS WHERE USERNAME=? AND ROLE='user'";
        response.getWriter().println("Docs: http://example.com/help /* keep */ // keep");
        try {
            java.sql.PreparedStatement statement =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection()
                            .prepareStatement(sql);
            statement.setString(1, param);
            statement.execute();
            org.owasp.benchmark.helpers.DatabaseHelper.printResults(statement, sql, response);
        } catch (java.sql.SQLException e) {
            throw new ServletException(e);
        }
    }
}
