#!/usr/bin/python3
# -*- coding: utf-8 -*-
import argparse, subprocess, sys, requests, os 
import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

print("\n")
print(""" ▄▄▄       ██▀███  ▄▄▄█████▓▓█████  ███▄ ▄███▓ ██▓  ██████ 
▒████▄    ▓██ ▒ ██▒▓  ██▒ ▓▒▓█   ▀ ▓██▒▀█▀ ██▒▓██▒▒██    ▒ 
▒██  ▀█▄  ▓██ ░▄█ ▒▒ ▓██░ ▒░▒███   ▓██    ▓██░▒██▒░ ▓██▄   
░██▄▄▄▄██ ▒██▀▀█▄  ░ ▓██▓ ░ ▒▓█  ▄ ▒██    ▒██ ░██░  ▒   ██▒
 ▓█   ▓██▒░██▓ ▒██▒  ▒██▒ ░ ░▒████▒▒██▒   ░██▒░██░▒██████▒▒
 ▒▒   ▓▒█░░ ▒▓ ░▒▓░  ▒ ░░   ░░ ▒░ ░░ ▒░   ░  ░░▓  ▒ ▒▓▒ ▒ ░
  ▒   ▒▒ ░  ░▒ ░ ▒░    ░     ░ ░  ░░  ░      ░ ▒ ░░ ░▒  ░ ░
  ░   ▒     ░░   ░   ░         ░   ░      ░    ▒ ░░  ░  ░  
      ░  ░   ░                 ░  ░       ░    ░        ░  

            \033[33m Scanner de vulnérabilité XSS\033[33m 
        \033[33m Developpeur : https://github.com/haisenberg\033[33m""")
print("\n")
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}

    action = form.attrs.get("action").lower()

    method = form.attrs.get("method", "get").lower()

    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


def scan_xss(url):
    forms = get_all_forms(url)
    print(f"\033[35m [+] Artemis à détécter {len(forms)} faille XSS sur {url}.\033[35m")
    js_script = "<script>alert(’1’)</script>"
    is_vulnerable = False
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"\033[31m******************************************\033[31m")
            print(f"[+] XSS vulnérabilité sur {url}")
            print(f"[*] Détail :")
            pprint(form_details)
            print(f"\033[31m******************************************\033[31m")
            is_vulnerable = True

    return is_vulnerable

if __name__ == "__main__":
    print("\033[32m ✓ (exemple : https://site.com/)\033[32m")
    print("\n")
    url = input("\033[31m ► Scanner un site web : \033[31m")
    print("\n")
    print(scan_xss(url))
