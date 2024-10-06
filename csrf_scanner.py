import requests
from bs4 import BeautifulSoup

def scan_for_csrf(url):
    """
    Scans a given URL for potential CSRF vulnerabilities.

    Args:
        url: The URL of the web page to scan.

    Returns:
        A list of dictionaries, where each dictionary represents a potentially vulnerable form
        and contains the form's action URL and its HTML.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes

        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        vulnerable_forms = []

        for form in forms:
            # Check if the form has a CSRF token field
            if not form.find('input', {'name': 'csrf_token'}):  # Adjust the field name if necessary
                action_url = form.get('action') or url  # Use the form's action or the base URL
                vulnerable_forms.append({'action': action_url, 'html': str(form)})

        return vulnerable_forms

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")
        return []

if __name__ == '__main__':
    target_url = input("Enter the URL to scan: ")
    vulnerable_forms = scan_for_csrf(target_url)

    if vulnerable_forms:
        print("Potential CSRF vulnerabilities found in the following forms:")
        for form in vulnerable_forms:
            print(f"Action URL: {form['action']}\nForm HTML: {form['html']}\n")
    else:
        print("No potential CSRF vulnerabilities found.")