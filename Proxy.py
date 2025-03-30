# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import time

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  serverSocket.bind((proxyHost, proxyPort))
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  serverSocket.listen(5)
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
    clientSocket, addr = serverSocket.accept()
    print ('Received a connection from:', addr)
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  if len(requestParts) < 3:
    print('Invalid HTTP request')
    clientSocket.close()
    continue
    
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
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

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
    
    if not fileExists:
        raise FileNotFoundError("Cache file not found")
    
    # Get file modification time to check if cache is fresh
    mod_time = os.path.getmtime(cacheLocation)
    current_time = time.time()
    
    # Read the file content
    with open(cacheLocation, "rb") as cacheFile:
        cache_content = cacheFile.read()
    
    # Check for max-age directive in cached response
    cache_control_match = re.search(rb'Cache-Control:.*?max-age=(\d+)', cache_content, re.IGNORECASE)
    if cache_control_match:
        max_age = int(cache_control_match.group(1))
        cache_age = current_time - mod_time
        
        # If cache is stale, raise exception to trigger cache miss handling
        if cache_age > max_age and max_age > 0:
            print(f"Cache is stale. Age: {cache_age}s, Max-Age: {max_age}s")
            raise FileNotFoundError("Cache is stale")

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    clientSocket.sendall(cache_content)
    
    print ('Sent cached content to the client')
  except Exception as e:
    # cache miss.  Get resource from origin server
    print(f"Cache miss: {str(e)}")
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      originServerSocket.connect((address, 80))
      originServerSocket.settimeout(10)  # Set timeout to prevent hanging
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      originServerRequest = method + " " + resource + " HTTP/1.1"
      originServerRequestHeader = "Host: " + hostname + "\r\nConnection: close"

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
        clientSocket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\nFailed to send request to origin server")
        clientSocket.close()
        originServerSocket.close()
        continue

      print('Request sent to origin server\n')

      # Get the response from the origin server
      response_bytes = b""
      while True:
          try:
              data = originServerSocket.recv(BUFFER_SIZE)
              if len(data) == 0:
                  break
              response_bytes += data
          except socket.timeout:
              print("Connection to origin server timed out")
              if len(response_bytes) == 0:
                  clientSocket.sendall(b"HTTP/1.1 504 Gateway Timeout\r\n\r\nConnection to origin server timed out")
                  clientSocket.close()
                  originServerSocket.close()
                  continue
              break

      # Check if it's a redirect response
      is_redirect = False
      if b'HTTP/1.1 301' in response_bytes[:20] or b'HTTP/1.1 302' in response_bytes[:20]:
          print("Detected redirect response")
          is_redirect = True

      # Send the response to the client
      clientSocket.sendall(response_bytes)

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      
      # Save origin server response in the cache file
      # Only cache 200 OK responses and redirects
      status_code_match = re.search(rb'HTTP/1.1 (\d+)', response_bytes)
      if status_code_match:
          status_code = int(status_code_match.group(1))
          if status_code == 200 or is_redirect:
              with open(cacheLocation, 'wb') as cacheFile:
                  cacheFile.write(response_bytes)
              print(f"Cached response with status code {status_code}")
          else:
              print(f"Not caching response with status code {status_code}")
      
      print ('Response handled')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except socket.timeout:
      print("Connection to origin server timed out")
      clientSocket.sendall(b"HTTP/1.1 504 Gateway Timeout\r\n\r\nConnection to origin server timed out")
    except socket.gaierror:
      print("DNS resolution failed for: " + hostname)
      clientSocket.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\nFailed to resolve hostname")
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)
      clientSocket.sendall(f"HTTP/1.1 502 Bad Gateway\r\n\r\nOrigin server request failed: {err.strerror}".encode())

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')