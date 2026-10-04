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

@WebServlet(value = "/cmdi-00/BenchmarkTest00017")
public class BenchmarkTest00017 extends HttpServlet {

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

        String param = "noCookieValueSupplied";
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (javax.servlet.http.Cookie cookie : cookies) {
                if (cookie.getName().equals("BenchmarkTest00017")) {
                    param = java.net.URLDecoder.decode(cookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        java.util.List<String> argList = new java.util.ArrayList<String>();
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + param);
        ProcessBuilder pb = new ProcessBuilder(argList);
        pb.start();
    }
}
