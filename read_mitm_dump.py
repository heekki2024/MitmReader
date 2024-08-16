#!/usr/bin/env python
"""
Read a mitmproxy dump file.
"""
import excel_IO

import pprint
import sys
import json

from mitmproxy import http
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException
from urllib.parse import parse_qs
import os

# Enable ANSI escape sequences in Windows PowerShell
os.system("")


def validate_and_read_file():
    if len(sys.argv) != 2:
        print("Error: dump file required!")
        print(f"Usage: {sys.argv[0]} mitm_dump_file")
        exit(1)


    #로그 파일 이름만 반환
    return sys.argv[1]
        # pp = pprint.PrettyPrinter(indent=4)
        # trackerList = excel_IO.excel_trackerList_input()
        
def process_request_tracker(f, trackerList):
    #print(f)
    #isinstance(인스턴스, 데이터나 클래스 타입)
    #숫자 33이 int타입인지 확인이 필요하다면 result = isinstance(33, int)
    if isinstance(f, http.HTTPFlow):
        print("\n!===============================!\n")

        request = f.request

        method = request.method
        host = request.host
       
        if excel_IO.match_trackerList(trackerList, host):
            print(method, host)
            if method == 'GET':
                print("\033[95m" + "GET@" + "\033[0m")

            print(f"path: {request.path}")
            
            queries = request.query.items()
            if len(queries) > 0:
                print("queries: [")
                for k, v in queries:
                    print(f"\t{k}={v}")
                print("]")
            else:
                print("queries: []")


            print("\n----------------------\n")
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


            print("\n----------------------\n")
            #------------------------------------
            
            if method == "POST":
                process_post_request(request, contentType, contentLength)
            else:
                print("NONE")

            print("\n!===============================!\n")
        else:
            print("매칭되는 호스트 없음")


def process_request_personInfo(f, prsnlList):
    #print(f)
    #isinstance(인스턴스, 데이터나 클래스 타입)
    #숫자 33이 int타입인지 확인이 필요하다면 result = isinstance(33, int)
    if isinstance(f, http.HTTPFlow):
        print("\n!===============================!\n")

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

        print("\n----------------------\n")
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


        print("\n----------------------\n")
        #------------------------------------
        
        if method == "POST":
            process_post_request(request, contentType, contentLength)
        else:
            print("NONE")

        print("\n!===============================!\n")



def process_post_request(request, contentType, contentLength):
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
        # Initialize colorama

        # Print text in blue
        print("\033[93m" + "어떤 내용이 있다" + "\033[0m")
    else:
        print("\033[93m" + "POST이긴 하다" + "\033[0m")

def process_flows(logfile_name, mode):

    
    try:
        with open(logfile_name, "rb") as logfile:
            freader = io.FlowReader(logfile)
            if mode == '1':
                for f in freader.stream():
                    trackerList = excel_IO.excel_trackerList_input()
                    process_request_tracker(f, trackerList)
                    print("")

            elif mode == '2':
                for f in freader.stream():
                    prsnlList = excel_IO.excel_prsnlList_input()
                    process_request_personInfo(f, prsnlList)
                    print("")
                # elif mode == 3:
                #     process_request(f)
                #     print("")    
                
    except FlowReadException as e:
        print(f"Flow file corrupted: {e}")


def main():
   
    mode = input("숫자를 입력")
    logfile_name = validate_and_read_file()
    
    
    process_flows(logfile_name, mode)

            


if __name__ == "__main__":
    main()
