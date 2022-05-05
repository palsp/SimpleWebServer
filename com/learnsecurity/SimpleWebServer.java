/***********************************************************************

   SimpleWebServer.java


   This toy web server is used to illustrate security vulnerabilities.
   This web server only supports extremely simple HTTP GET and HTTP PUT
   requests.

 ***********************************************************************/

package com.learnsecurity;

import java.io.*;
import java.net.*;
import java.util.*;
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;

public class SimpleWebServer {

  /* Run the HTTP server on this TCP port. */
  private static final int PORT = 8080;
  private static final String[] ALLOW_CONTENT_TYPE = { "text/plain" };

  /*
   * The socket used to process incoming connections from web clients
   */
  private static ServerSocket dServerSocket;

  public SimpleWebServer() throws Exception {
    dServerSocket = new ServerSocket(PORT);
  }

  public void run() throws Exception {
    while (true) {
      /* wait for a connection from a client */
      Socket s = dServerSocket.accept();

      /* then process the client's request */
      processRequest(s);
    }
  }

  private void logging(Socket s, String command, String path, Number statusCode, String userAgentLine) {
    try {
      DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
      String addr = s.getRemoteSocketAddress().toString().replace("/", "");
      String t = dtf.format(LocalDateTime.now());

      String userAgent = String.join("", new String[] { "\"", userAgentLine.split(":")[1], "\"" });

      String endpoint = String.join("", new String[] { "\"", command, " ", path, "\"" });

      String log = String.join(" ",
          new String[] { addr, "- -", "[", t, "]", endpoint, statusCode.toString(), userAgent });

      BufferedWriter out = new BufferedWriter(
          new FileWriter("access.log", true));

      // Writing on output stream
      out.write(log + "\n");
      // Closing the connection
      out.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /*
   * Reads the HTTP request from the client, and responds with the file the
   * user requested or a HTTP error code.
   */
  public void processRequest(Socket s) throws Exception {
    /* used to read data from the client */
    BufferedReader br = new BufferedReader(new InputStreamReader(
        s.getInputStream()));

    /* used to write data to the client */
    OutputStreamWriter osw = new OutputStreamWriter(s.getOutputStream());

    /* read the HTTP request from the client */
    String request = br.readLine();

    String command = null;
    String pathname = null;

    /* parse the HTTP request */
    StringTokenizer st = new StringTokenizer(request, " ");

    command = st.nextToken();
    pathname = st.nextToken();

    if (command.equals("GET")) {
      /*
       * if the request is a GET try to respond with the file the user is
       * requesting
       */
      String userAgent = this.getUserAgentLine(br);
      serveFile(s, osw, pathname, userAgent);
    } else if (command.equals("PUT")) {
      /*
       * if the request is a PUT try to store the file where the user is
       * requesting
       */
      storeFile(s, br, osw, pathname);

    } else {
      /*
       * if the request is a NOT a GET, return an error saying this server
       * does not implement the requested command
       */
      osw.write("HTTP/1.0 501 Not Implemented\n\n");
    }

    /* close the connection to the client */
    osw.close();
  }

  public void serveFile(Socket s, OutputStreamWriter osw, String pathname, String userAgent)
      throws Exception {
    FileReader fr = null;
    int c = -1;
    StringBuffer sb = new StringBuffer();

    /*
     * remove the initial slash at the beginning of the pathname in the
     * request
     */
    if (pathname.charAt(0) == '/')
      pathname = pathname.substring(1);

    /*
     * if there was no filename specified by the client, serve the
     * "index.html" file
     */
    if (pathname.equals(""))
      pathname = "index.html";

    /* try to open file specified by pathname */
    try {
      fr = new FileReader(pathname);
      c = fr.read();
    } catch (Exception e) {
      /*
       * if the file is not found,return the appropriate HTTP response
       * code
       */

      osw.write("HTTP/1.0 404 Not Found\n\n");
      this.logging(s, "GET", pathname, 404, userAgent);
      return;
    }

    /*
     * if the requested file can be successfully opened and read, then
     * return an OK response code and send the contents of the file
     */
    osw.write("HTTP/1.0 200 OK\n\n");
    this.logging(s, "GET", pathname, 200, userAgent);
    while (c != -1) {
      sb.append((char) c);
      c = fr.read();
    }
    osw.write(sb.toString());
  }

  public void storeFile(Socket s, BufferedReader br, OutputStreamWriter osw, String pathname) throws Exception {
    try {
      // code to read and print headers
      String userAgent = this.getUserAgentLine(br);

      String boundary = br.readLine();
      String contentDisposition = br.readLine();
      String contentType = br.readLine();

      if (!this.isValidContentDisposition(contentDisposition)) {
        osw.write("HTTP/1.0 400 Bad Request");
        this.logging(s, "PUT", pathname, 400, userAgent);
        return;
      }

      if (!this.isValidContentType(contentType)) {
        osw.write("HTTP/1.0 400 Bad Request");
        this.logging(s, "PUT", pathname, 400, userAgent);
        return;
      }

      String filename = this.randomFileName(contentType, pathname);

      FileWriter fw = new FileWriter("storage/" + filename);
      // read blank line between content attributes and body
      br.readLine();

      StringBuilder result = new StringBuilder();
      while (br.ready()) {
        String line = br.readLine();
        if (line.equals(boundary + "--")) {
          // check if the line reach boundary
          break;
        } else {
          result.append(line + '\n');
        }
      }

      fw.write(result.toString().trim());
      fw.close();
      osw.write("HTTP/1.0 201 Created");
      this.logging(s, "PUT", pathname, 201, userAgent);
    } catch (Exception e) {

      osw.write("HTTP/1.0 500 Internal Server Error");
    }
  }

  private String getUserAgentLine(BufferedReader br) throws Exception {
    String headerLine = null;
    String targetLine = ":";
    while ((headerLine = br.readLine()).length() != 0) {
      if (headerLine.toLowerCase().startsWith("user-agent")) {
        targetLine = headerLine;
      }
      System.out.println(headerLine);
    }

    return targetLine;
  }

  private String randomFileName(String fileType, String pathname) {
    return "random.txt";
  }

  private boolean isValidContentDisposition(String line) {
    String[] parts = line.split(";");
    String[] fieldNameParts = parts[1].split("=");
    if (!fieldNameParts[0].trim().equals("name")) {
      return false;
    } else if (!fieldNameParts[1].replace("\"", "").equals("file")) {
      return false;
    }

    return true;
  }

  private boolean isValidContentType(String line) {
    String[] parts = line.split(":");
    String contentType = parts[1].trim();

    for (int i = 0; i < ALLOW_CONTENT_TYPE.length; i++) {
      if (ALLOW_CONTENT_TYPE[i].equals(contentType)) {
        return true;
      }
    }

    return false;
  }

  /*
   * This method is called when the program is run from the command line.
   */
  public static void main(String argv[]) throws Exception {

    /* Create a SimpleWebServer object, and run it */
    SimpleWebServer sws = new SimpleWebServer();
    sws.run();
  }
}