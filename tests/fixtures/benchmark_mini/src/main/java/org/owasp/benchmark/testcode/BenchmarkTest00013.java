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

@WebServlet(value = "/xss-00/BenchmarkTest00013")
public class BenchmarkTest00013 extends HttpServlet {

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
        if (request.getHeader("BenchmarkTest00013") != null) {
            param = request.getHeader("BenchmarkTest00013"); // header value is not decoded
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");

        response.setHeader("X-XSS-Protection", "0");
        String note = "/* not a comment */ and // not a comment either";
        response.getWriter().println(note);
        response.getWriter()
                .print(org.apache.commons.text.StringEscapeUtils.escapeHtml4(param));
    }
}
