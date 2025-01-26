import time
import requests
from bs4 import BeautifulSoup

# URL of the endpoint to test
BASE_URL = "http://127.0.0.1:5000"
LOGIN_PAGE = "/login"
TEST_ENDPOINT = "/login"

# Test credentials for login endpoint
credentials = {
    "username_or_email": "TestUser3",  # Replace with a valid username or email
    "password": "NewPassword1234",      # Replace with a valid password
}

# Number of requests to simulate
NUM_REQUESTS = 10

def get_csrf_token(session, url):
    """Retrieve CSRF token from the login page."""
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
    return csrf_token

def main():
    with requests.Session() as session:
        # Step 1: Get the CSRF token
        csrf_token = get_csrf_token(session, BASE_URL + LOGIN_PAGE)
        print(f"Retrieved CSRF token: {csrf_token}")

        # Step 2: Add the CSRF token to the payload
        credentials['csrf_token'] = csrf_token

        print(f"Testing rate limiting on {BASE_URL + TEST_ENDPOINT}")

        for i in range(NUM_REQUESTS):
            try:
                # Step 3: Send a POST request to the endpoint
                response = session.post(BASE_URL + TEST_ENDPOINT, data=credentials)

                # Print relevant information about the response
                print(f"Request {i+1}: Status Code: {response.status_code}, Message: {response.reason}")

                # Simulate a delay between requests
                time.sleep(0.5)  # Adjust delay to test rate limiting

            except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")

        print("Test complete.")

if __name__ == "__main__":
    main()
