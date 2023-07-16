

import http.server
import ssl

# Set up server address and port
server_address = ('', 443)  # Use an empty string to listen on all available interfaces
keyfile="/etc/letsencrypt/live/ip.henryn.xyz/privkey.pem"
certfile='/etc/letsencrypt/live/ip.henryn.xyz/fullchain.pem'

# Create an HTTP server with SSL/TLS support
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile=certfile, keyfile=keyfile, server_side=True)

# Set the directory to serve files from
httpd.directory = 'public'

# Start the server
print('Starting HTTPS server on port 8000...')
httpd.serve_forever()
