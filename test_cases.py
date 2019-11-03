import unittest, requests
from bs4 import BeautifulSoup
import random

server_address="http://127.0.0.1:5000"
server_login=server_address + "/login"
server_register=server_address + "/register"
server_spellcheck=server_address + "/spell_check"
#print("Test Ping Pages")
TestUser = "TestUser" + str(random.randint(1,100))

class FeatureTest(unittest.TestCase):
    TESTING = True
    WTF_CSRF_ENABLED = False
    #check main page returns 200 OK
    def test_server_exists(self):
        response = requests.get(server_address)
        self.assertEqual(response.status_code, 200)
    #check login page returns 200 OK
    def test_login_page_exists(self):
        response = requests.get(server_login)
        self.assertEqual(response.status_code, 200)
    #check register page returns 200 OK
    def test_register_page_exists(self):
        response = requests.get(server_register)
        self.assertEqual(response.status_code, 200)
    #check spellcheck page returns 200 OK (note: unauthorized due to login requirement)
    def test_spellcheck_page_exists(self):
        response = requests.get(server_spellcheck)
        self.assertEqual(response.status_code, 200)
    
    #check registration functionality 
    def test_register(self):
        sess=requests.session()
        response=sess.get(server_register)
        soup=BeautifulSoup(response.text, 'html.parser')
        #print(soup.prettify())
        token=soup.find('input', {'name':'csrf_token'})['value']
        #print(token)

        post_data=('uname=%s&pword=%s&twofa=%s&csrf_token=%s' % (TestUser, TestUser, "10001234567", token))
        post_header={'Content-type': 'application/x-www-form-urlencoded'} #content type not working with multipart/form-data or text/plain
        response2=sess.post(url=server_register, headers=post_header, data=post_data)
        
        soup2=BeautifulSoup(response2.text, 'html.parser')
        #print(soupResult)
        result=soup2.find(id='success').text
        #print(soupAnswer)
        self.assertEqual(result, 'success')

    def test_register_existing_user(self):
        sess=requests.session()
        response=sess.get(server_register)
        soup=BeautifulSoup(response.text, 'html.parser')
        token=soup.find('input', {'name':'csrf_token'})['value']

        post_data=('uname=%s&pword=%s&twofa=%s&csrf_token=%s' % (TestUser, TestUser, "10001234567", token)) # make sure uname matches above test
        post_header={'Content-type': 'application/x-www-form-urlencoded'} 
        response2=sess.post(url=server_register, headers=post_header, data=post_data)
        
        soup2=BeautifulSoup(response2.text, 'html.parser')
        result=soup2.find(id='success').text
        self.assertEqual(result, 'failure')

    def test_invalid_login(self):
        sess=requests.session()
        response=sess.get(server_login)
        soup=BeautifulSoup(response.text, 'html.parser')
        token=soup.find('input', {'name':'csrf_token'})['value']
        
        post_data=('uname=%s&pword=%s&twofa=%s&csrf_token=%s' % ("TestUser50000", "TestUser50000", "10001234567", token)) # make sure uname not in dict or credentials mismatch
        post_header={'Content-type': 'application/x-www-form-urlencoded'} 
        response2=sess.post(url=server_login, headers=post_header, data=post_data)

        soup2=BeautifulSoup(response2.text, 'html.parser')
        result=soup2.find(id='result').text
        self.assertEqual(result, 'Incorrect')

    def test_valid_login(self):
        sess=requests.session()
        response=sess.get(server_login)
        soup=BeautifulSoup(response.text, 'html.parser')
        token=soup.find('input', {'name':'csrf_token'})['value']
        
        post_data=('uname=%s&pword=%s&twofa=%s&csrf_token=%s' % (TestUser, TestUser, "10001234567", token)) # make sure uname not in dict or credentials mismatch
        post_header={'Content-type': 'application/x-www-form-urlencoded'} 
        response2=sess.post(url=server_login, headers=post_header, data=post_data)

        soup2=BeautifulSoup(response2.text, 'html.parser')
        result=soup2.find(id='result').text
        self.assertEqual(result, 'Success')

    def test_spell_check(self): #must be logged in first
        sess=requests.session()
        response=sess.get(server_login)
        soup=BeautifulSoup(response.text, 'html.parser')
        token=soup.find('input', {'name':'csrf_token'})['value']
        
        post_data=('uname=%s&pword=%s&twofa=%s&csrf_token=%s' % (TestUser, TestUser, "10001234567", token)) # make sure uname not in dict or credentials mismatch
        post_header={'Content-type': 'application/x-www-form-urlencoded'} 
        response2=sess.post(url=server_login, headers=post_header, data=post_data)

        
        #sess=requests.session()
        response=sess.get(server_spellcheck)
        soup=BeautifulSoup(response.text, 'html.parser')
        #token=soup.find('input', {'name':'csrf_token'})['value']
        #print(token)
        
        spellinput="The quick broown faax jumped over the lazzy dog."
        post_data=('inputtext=%s&csrf_token=%s' % (spellinput, token)) #enter
        post_header={'Content-type': 'application/x-www-form-urlencoded'} 
        response2=sess.post(url=server_spellcheck, headers=post_header, data=post_data)

        soup2=BeautifulSoup(response2.text, 'html.parser')
        #print(soup2)
        #result=soup2.find('input', {'name':'misspelled'})['value']
        #print(result)
        result=soup2.find(id='misspelled').text
        print(result)
        result_fix=result.lstrip().strip()
        print(result_fix)
        #self.assertEqual (misspelled == "broown, faax, lazzy")

        #soup2=BeautifulSoup(response2.text, 'html.parser')
        #result=soup2.find(id='misspelled')
        #print(result)

        self.assertEqual(result_fix, 'broown, faax, lazzy')

    def test_debugger(self):
        response=requests.get(server_register)
        #print(response.status_code)
        #print(response.headers)
        soup=BeautifulSoup(response.text, 'html.parser')
        #print(soup)
        links=soup.find_all("input")
        #print(links)
        #print(soup.p)
        
