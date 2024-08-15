#!/usr/bin/env python
"""
Read a mitmproxy dump file.
"""

import pprint
import sys
import json

from mitmproxy import http
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException
from urllib.parse import parse_qs

if len(sys.argv) != 2:
    print("Error: dump file required!")
    print(f"Usage: {sys.argv[0]} mitm_dump_file")
    exit(1)

with open(sys.argv[1], "rb") as logfile:
    freader = io.FlowReader(logfile)
    pp = pprint.PrettyPrinter(indent=4)
    try:
        for f in freader.stream():
            #print(f)
            #isinstance(인스턴스, 데이터나 클래스 타입)
            #숫자 33이 int타입인지 확인이 필요하다면 result = isinstance(33, int)
            if isinstance(f, http.HTTPFlow):
                print("===============================")
                request = f.request

                method = request.method
                host = request.host

                print(method, host)
                print(f"path: {request.path}")
                
                queries = request.query.items()
                if len(queries) > 0:
                    print("queries: [")
                    for k, v in queries:
                        print(f"\t{k}={v}")
                    print("]")
                else:
                    print("queries: []")

                #------------------------------------

                contentType = ""
                contentLength = 0

                headers = request.headers.items()
                if len(headers) > 0:
                    print("headers: [")
                    for k, v in headers:
                        print(f"\t{k}={v}")
                        if k.casefold() == "Content-Type".casefold():
                            vv = v.split(";")
                            contentType = vv[0]
                        elif k.casefold() == "Content-Length".casefold():
                            contentLength = int(v)
                    print("]")
                else:
                    print("headers: []")

                #------------------------------------

                if method == "POST":
                    if contentLength > 0:
                        print(f"=> {contentType}: [")
                        text = request.get_text(False)
                        match contentType:
                            case "application/x-www-form-urlencoded":
                                data = parse_qs(text)
                                for k, v in data.items():
                                    print(f"\t{k}={v}")
                            case "application/json":
                                data = json.loads(text)
                                print(json.dumps(data, indent=4))
                            case "text/plain":
                                print(text)
                            case _:
                                print("\t** SKIP **")
                        print("]")

                print("---------------------------------")
                # response = f.response
                # if response is not None:
                #     statusCode = response.status_code
                #     print(f"Status: {statusCode}")

                #     if statusCode == 200:
                #         contentType = ""
                #         contentLength = 0

                #         headers = response.headers.items()
                #         if len(headers) > 0:
                #             for k, v in headers:
                #                 if k.casefold() == "Content-Type".casefold():
                #                     print(f"Content-Type: {v}")
                #                     vv = v.split(";")
                #                     contentType = vv[0]
                #                 elif k.casefold() == "Content-Length".casefold():
                #                     print(f"Content-Length: {v}")
                #                     contentLength = int(v)
                    
                #         if contentType != "":
                #             print(f"<= {contentType}: [")
                #             text = response.get_text(False)
                #             match contentType:
                #                 case "application/x-www-form-urlencoded":
                #                     data = parse_qs(text)
                #                     for k, v in data.items():
                #                         print(f"\t{k}={v}")
                #                 case "application/json":
                #                     data = json.loads(text)
                #                     print(json.dumps(data, indent=4))
                #                 case "text/plain" | "text/html":
                #                     try:
                #                         data = json.loads(text)
                #                         print(json.dumps(data, indent=4))
                #                     except ValueError:
                #                         print(text)
                #                 case _:
                #                     print("\t** SKIP **")
                #             print("]")

            print("")
    except FlowReadException as e:
        print(f"Flow file corrupted: {e}")
        