#!/usr/bin/env python3

import sys
import time
import subprocess

username=sys.argv[1]
password=sys.argv[2]

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

def okta_status():
    output = b"0"
    try:
        output = subprocess.check_output(['curl', '-s', '-I', '-o', '/dev/null', '-w', '%{http_code}', "http://localhost:8180"])
    except subprocess.CalledProcessError as e:
        return output.decode('ascii')
    return output.decode('ascii')

def okta_login(driver):
    try:
        driver.get('http://localhost:8180')
        name_form = driver.find_element_by_id('okta-signin-username')
        if name_form is not None:
            name_form.send_keys(username)
    except:
        pass
        return False
    try:
        pwd_form = driver.find_element_by_id('okta-signin-password')
        if pwd_form is not None:
            pwd_form.send_keys(password)
    except:
        pass
        return False
    try:
        submit_button = driver.find_element_by_id('okta-signin-submit')
        if submit_button is not None:
            submit_button.click()
    except:
        pass
        return False
    return True

if __name__ == '__main__':
    status = okta_status()
    while status != "200":
        print('Login URL not ready %s' % status, flush=True)
        time.sleep(5)
        status = okta_status()

    status = okta_status()
    while status != "201":
        driver = webdriver.Chrome(chrome_options=options)
        print('Not yet logged in %s' % status, flush=True)
        login = okta_login(driver)
        print('Okta login status %s' % login, flush=True)
        time.sleep(30)
        status = okta_status()
        driver.quit()
    print('Logged in', flush=True)

