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

match = False

# def validate_and_read_file():
#     if len(sys.argv) != 2:
#         print("Error: dump file required!")
#         print(f"Usage: {sys.argv[0]} mitm_dump_file")
#         exit(1)


#     #로그 파일 이름만 반환
#     return sys.argv[1]
#         # pp = pprint.PrettyPrinter(indent=4)
#         # trackerList = excel_IO.excel_trackerList_input()
        
def read_dump():
    dump_path = input("dump파일의 경로를 입력해주세요: ")

    return dump_path

trackercount = 0
def process_request_tracker(f, trackerList):
    global trackercount
    #print(f)
    #isinstance(인스턴스, 데이터나 클래스 타입)
    #숫자 33이 int타입인지 확인이 필요하다면 result = isinstance(33, int)
    if isinstance(f, http.HTTPFlow):
        print("\n!===============================!\n")
        

        request = f.request

        method = request.method
        host = request.host
       
        if excel_IO.match_trackerList(trackerList, host):
            trackercount+=1
            print(f"\033[96m" + str({trackercount}) + "\033[0m")
            print(method, host)
            if method == 'GET':
                print("\033[95m" + "GET" + "\033[0m")

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
                    print(f"\t{k}: {v}")
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

count = 0
def process_request_personInfo(f, prsnlList, package_name):
    global match
    #print(f)
    #isinstance(인스턴스, 데이터나 클래스 타입)
    #숫자 33이 int타입인지 확인이 필요하다면 result = isinstance(33, int)
    if isinstance(f, http.HTTPFlow):
        print("\n!===============================!\n")

        request = f.request

        method = request.method
        host = request.host
        
        word_pattern = rf'{excel_IO.re.escape(package_name)}\b'

        if excel_IO.re.search(word_pattern, host, excel_IO.re.IGNORECASE):
            return
        # print(method, host)
        # print(f"path: {request.path}")
        
        queries = request.query.items()
        if len(queries) > 0:
            # print("queries: [")
            for k, v in queries:
                if excel_IO.match_prsnlList(prsnlList, (k, v)):
                    match = True
            #     print(f"\t{k}={v}")
            # print("]")


        contentType = ""
        contentLength = 0

        headers = request.headers.items()
        if len(headers) > 0:
            # print("headers: [")
            for k, v in headers:
                # print(f"\t{k}: {v}")
                if k.casefold() == "Content-Type".casefold():
                    vv = v.split(";")
                    contentType = vv[0]
                elif k.casefold() == "Content-Length".casefold():
                    contentLength = int(v)

                if excel_IO.match_prsnlList(prsnlList, (k, v)):
                    match = True

            # print("]")

       
        if method == "POST":
            if contentLength > 0:
                text = request.get_text(False)
                # print("Received JSON text:", text)  # 디버그용으로 추가
                try:
                    match contentType:
                        case "application/x-www-form-urlencoded":
                            data = parse_qs(text)
                            if excel_IO.match_prsnlList(prsnlList, data.items()):
                                match = True
                        case "application/json":
                            data = json.loads(text)
                            if excel_IO.match_prsnlList(prsnlList, json.dumps(data, indent=4)):
                                match = True
                        case "text/plain":
                            if excel_IO.match_prsnlList(prsnlList, text):
                                match = True
                except json.JSONDecodeError as e:
                    print(f"JSON Decode Error: {e}")
                    print("Invalid JSON:", text)
#-------------------------------------------------------------------------------------------------------------------
        global count
        if match == True:
            count+=1
            print(f"\033[96m" + str({count}) + "\033[0m")
            
            print()
            if method == 'GET':
                print("\033[95m" + "GET" + "\033[0m")
            
            print(method, host)
            print(f"path: {request.path}")
            
            if len(queries) > 0:
                print("queries: [")
                for k, v in queries:
                    print(f"\t{k}={v}")
                print("]")
            else:
                print("queries: []")

            print("\n----------------------\n")


            if len(headers) > 0:
                print("headers: [")
                for k, v in headers:
                    print(f"\t{k}: {v}")
                print("]")

            else:
                print("headers: []")

            print("\n----------------------\n")

            if method == "POST":
                process_post_request(request, contentType, contentLength)
            else:
                print("NONE")
                        
            # 매칭된 데이터를 저장할 리스트
            data_to_write = []

            # 메소드와 호스트 추가
            data_to_write.append(method)
            data_to_write.append(host)

            data_to_write.append(f"path: {request.path}")

            # 쿼리 문자열 추가
            queries = request.query.items()
            if len(queries) > 0:
                data_to_write.append("[")
                for k, v in queries:
                    data_to_write.append(f"{k}={v}")
                data_to_write.append("]")

            else:
                data_to_write.append("queries: []")

            # 헤더 추가
            headers = request.headers.items()
            if len(headers) > 0:
                data_to_write.append("[")
                for k, v in headers:
                    data_to_write.append(f"{k}: {v}")
                data_to_write.append("]")

            else:
                data_to_write.append("headers: []")

            if method == "POST":
                process_post_request_excel(request, contentType, contentLength, data_to_write)
            else:
                data_to_write.append("headers: []")
                        

            # 데이터를 엑셀에 기록
            excel_IO.write_to_excel(host, data_to_write, package_name)


def process_post_request(request, contentType, contentLength):
    if contentLength > 0:
        try:
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
        except json.JSONDecodeError as e:
            print("\033[95m" + "json error" + "\033[0m")

            print(f"JSON Decode Error: {e}")
            print("Invalid JSON:", text)                     

        print("\033[93m" + "어떤 내용이 있다" + "\033[0m")
        return True
    else:
        print("\033[93m" + "POST이긴 하다" + "\033[0m")

def process_post_request_excel(request, contentType, contentLength, data_to_write):
    if contentLength > 0:
        try:
            # 엑셀에서 수식 오류를 방지하기 위해 특수 문자를 이스케이프 처리
            def escape_excel_formula(value):
                if isinstance(value, str):
                    # 문자열이 수식으로 인식되지 않게 앞에 '를 추가
                    if value.startswith(('=', '+', '-', '@')):
                        return f"'{value}"
                    else:
                        return value
                elif isinstance(value, list):
                    # 리스트인 경우 각각의 요소를 이스케이프 처리
                    return [escape_excel_formula(v) for v in value]
                return value

            data_to_write.append(f"> {contentType}: [")

            text = request.get_text(False)
            match contentType:
                case "application/x-www-form-urlencoded":
                    data = parse_qs(text)
                    for k, v in data.items():
                        escaped_key = escape_excel_formula(k)
                        escaped_value = escape_excel_formula(v)
                        data_to_write.append(f"\t{escaped_key}={escaped_value}")

                case "application/json":
                    data = json.loads(text)
                    if isinstance(data, dict):
                        for k, v in data.items():
                            escaped_key = escape_excel_formula(k)
                            escaped_value = escape_excel_formula(v)
                            data_to_write.append(f"{escaped_key}: {escaped_value}")
                    elif isinstance(data, list):
                        for i, item in enumerate(data):
                            escaped_item = escape_excel_formula(item)
                            data_to_write.append(f"{i}: {escaped_item}")

                case "text/plain":
                    escaped_text = escape_excel_formula(text)
                    data_to_write.append(escaped_text)

                case _:
                    data_to_write.append("\t** SKIP **")

            data_to_write.append("]")  # 데이터의 끝에 닫는 대괄호 추가

        except json.JSONDecodeError as e:
            print(f"JSON Decode Error: {e}")
            print("Invalid JSON:", text)
    else:
        data_to_write.append("NONE")


def process_flows(dump_path, mode):   
    package_name = os.path.basename(dump_path)

    try:
        with open(dump_path, "rb") as logfile:
            freader = io.FlowReader(logfile)
            if mode == '1':
                for f in freader.stream():
                    trackerList = excel_IO.excel_trackerList_input()
                    process_request_tracker(f, trackerList)
                    print("")

            elif mode == '2':
                totcount = 0
                for f in freader.stream():
                    global match
                    
                    prsnlList = excel_IO.excel_prsnlList_input()
                    process_request_personInfo(f, prsnlList, package_name)
                    print("")
                    match = False
                    totcount += 1
                    print(f"\033[94m" + "total count" + str({totcount}) + "\033[0m")

                    print("\n!===============================!\n")

                    
                # elif mode == 3:
                #     process_request(f)
                #     print("")    
                
    except FlowReadException as e:
        print(f"Flow file corrupted: {e}")


def main():
   
    mode = input("숫자를 입력: ")
    dump_path = read_dump()
    
    
    process_flows(dump_path, mode)

            


if __name__ == "__main__":
    main()
