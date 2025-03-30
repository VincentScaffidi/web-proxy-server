# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
# Add these imports at the top
from email.utils import parsedate_to_datetime
import threading
import datetime
import time

def prefetch_links(html_content, base_url):
    """Find and cache linked resources (href/src) in HTML."""
    links = re.findall(r'(?:href|src)=["\'](.*?)["\']', html_content)
    for link in links:
        if not link.startswith(('http://', 'https://')):
            link = base_url + '/' + link.lstrip('/')  # Resolve relative URLs
        threading.Thread(target=cache_resource, args=(link,)).start()

def cache_resource(url):
    try:
        # Parse hostname:port and resource from URL
        url = url.replace('http://', '').replace('https://', '')
        host_port_part, _, resource = url.partition('/')
        if ':' in host_port_part:
            host, port = host_port_part.split(':', 1)
            port = int(port)
        else:
            host, port = host_port_part, 80
        
        # Create socket and request
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        request = f"GET /{resource} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        s.send(request.encode())
        
        # Cache the response (same logic as main code)
        response = s.recv(BUFFER_SIZE)
        # ... [Save to cache directory] ...
    except:
        pass
# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening, this is a test commit
try:
  # Create a server socket
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ INSERT CODE ~~~~
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  # Under "Bind the the server socket to a host and port"
  serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  serverSocket.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket.listen(5)
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = serverSocket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  # Split hostname:port and resource
  resourceParts = URI.split('/', 1)
  if ':' in resourceParts[0]:
      hostname, port = resourceParts[0].split(':', 1)
      port = int(port)
  else:
      hostname = resourceParts[0]
      port = 80  # Default to port 80

  resource = '/' + resourceParts[1] if len(resourceParts) > 1 else '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    cache_valid = True
    try:
        with open(cacheLocation, 'r') as f:
            content = f.read()
        
        # Check max-age
        max_age_match = re.search(r'Cache-Control:.*?max-age=(\d+)', content, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            file_age = time.time() - os.path.getmtime(cacheLocation)
            if file_age > max_age:
                cache_valid = False
        
        # Check Expires header
        expires_match = re.search(r'Expires: (.+)', content, re.IGNORECASE)
        if expires_match:
            expires_str = expires_match.group(1).strip()
            expires_dt = parsedate_to_datetime(expires_str)
            if datetime.datetime.now(datetime.timezone.utc) > expires_dt:
                cache_valid = False
        
        if not cache_valid:
            print("Cache expired. Fetching from origin.")
            raise Exception("Cache expired")
        
        cacheData = content.splitlines(keepends=True)
    except:
        raise Exception("Cache invalid")

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    for line in cacheData:
      clientSocket.send(line.encode())
    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address, port))  # Use parsed port
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequest = method + " " + resource + " HTTP/1.1"
      originServerRequestHeader = "Host: " + hostname
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      response_bytes = b""
      while True:
          data = originServerSocket.recv(BUFFER_SIZE)
          if len(data) > 0:
              response_bytes += data
          else:
              break

      # ~~~~ END CODE INSERT ~~~~ check

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(response_bytes)
      # ~~~~ END CODE INSERT ~~~~

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      cacheFile = open(cacheLocation, 'wb')

      # Save origin server response in the cache file
      # ~~~~ INSERT CODE ~~~~
      cacheFile.write(response_bytes)
      if 'text/html' in response_bytes.decode('utf-8', errors='ignore'):
        prefetch_links(
          response_bytes.decode('utf-8', errors='ignore').split('\r\n\r\n', 1)[1],
          f"http://{hostname}"
        )
      # ~~~~ END CODE INSERT ~~~~
      cacheFile.close()
      print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
