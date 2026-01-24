from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/')
def home():
    return """
    <h1>Internal server</h1>
    <p>Use the /fetch endpoint to test.</p>
    <p>Example: <a href="/fetch?url=http://example.com">/fetch?url=http://example.com</a></p>
    """

@app.route('/fetch')
def fetch_url():
    # GET the 'url' parameter from the request
    target_url = request.args.get('url')
    
    if not target_url:
        return "Error: Missing 'url' parameter", 400

    print(f"[Server] Received request to fetch: {target_url}")

    try:
        # --- THE VULNERABILITY ---
        # The server blindly fetches the user-supplied URL
        # AND returns the response content (Non-Blind)
        resp = requests.get(target_url, timeout=5)
        
        # We return the content directly to the user
        return resp.content
        
    except Exception as e:
        return f"Error fetching URL: {str(e)}", 500

if __name__ == '__main__':
    # Running on 0.0.0.0 allows you to access it from other devices if needed
    # debug=True allows you to see errors in the console
    print("Starting vulnerable server on http://127.0.0.1:80")
    app.run(host='127.0.0.1', port=8000)
