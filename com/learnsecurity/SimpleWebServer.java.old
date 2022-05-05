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

public class SimpleWebServer2 {

  // ...
  /* Run the HTTP server on this TCP port. */
  private static final int PORT = 8080;

  private static final String[] ALLOW_FILES = {"index.html"};
  private static final String[] WHITELIST_MIME_TYPES = {".jpeg",".jpg",".png"};

  /*
   * The socket used to process incoming connections from web clients
   */
  private static ServerSocket dServerSocket;

  private boolean checkFile(String pathname){
    for(int i = 0; i < ALLOW_FILES.length; i++){
      if(ALLOW_FILES[i].equals(pathname)){
        return true;
      }
    }

    return false;
  }

  public SimpleWebServer() throws Exception {
    dServerSocket = new ServerSocket(PORT);
  }

  public void run() throws Exception {
    System.out.println("Running on port 8080....");
    while (true) {
      /* wait for a connection from a client */
      Socket s = dServerSocket.accept();

      /* then process the client's request */
      processRequest(s);
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

    // DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
    // char dataType = in.readChar();
    // int length = in.readInt();
    // System.out.println(dataType);
    // System.out.println(length);

    command = st.nextToken();
    pathname = st.nextToken();


    if (command.equals("GET")) {
      /*
       * if the request is a GET try to respond with the file the user is
       * requesting
       */
      serveFile(osw, pathname);
    } else if (command.equals("PUT")) {
      /*
       * if the request is a PUT try to store the file where the user is
       * requesting
       */
      storeFile(br, osw, pathname);
      // serveFile(osw, pathname);
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

  public void serveFile(OutputStreamWriter osw, String pathname)
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
    boolean valid = checkFile(pathname);
    if (pathname.equals("") || !valid)
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
      return;
    }

    /*
     * if the requested file can be successfully opened and read, then
     * return an OK response code and send the contents of the file
     */
    osw.write("HTTP/1.0 200 OK\n\n");
    while (c != -1) {
      sb.append((char) c);
      c = fr.read();
    }
    osw.write(sb.toString());
  }

  public void storeFile(BufferedReader br, OutputStreamWriter osw,
      String pathname) throws Exception {
    FileWriter fw = null;
    try {
      fw = new FileWriter(pathname);
      String s = br.readLine();

      while (s != null) {

        fw.write(s);
        s = br.readLine();
      }
      fw.close();
      osw.write("HTTP/1.0 201 Created");
    } catch (Exception e) {
      e.printStackTrace();
      osw.write("HTTP/1.0 500 Internal Server Error");
    }
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