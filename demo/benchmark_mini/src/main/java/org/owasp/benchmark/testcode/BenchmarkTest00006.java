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

@WebServlet(value = "/sqli-00/BenchmarkTest00006")
public class BenchmarkTest00006 extends HttpServlet {

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

        String param = request.getParameter("BenchmarkTest00006");
        if (param == null) param = "";

        String bar;
        int num = 106;
        bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
        String sql = "SELECT * FROM USERS WHERE USERNAME='" + bar + "'";
        try {
            java.sql.Statement statement =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
            statement.execute(sql);
            org.owasp.benchmark.helpers.DatabaseHelper.printResults(statement, sql, response);
        } catch (java.sql.SQLException e) {
            throw new ServletException(e);
        }
    }
}
