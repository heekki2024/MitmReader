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

import gzip
import zlib
from io import BytesIO




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
    matched_patterns = []


    #print(f)
    #isinstance(인스턴스, 데이터나 클래스 타입)
    #숫자 33이 int타입인지 확인이 필요하다면 result = isinstance(33, int)
    if isinstance(f, http.HTTPFlow):
        print("\n!===============================!\n")

        request = f.request

        method = request.method
        host = request.host
        
        print(request)
        print(method)
        print(host)

        word_pattern = rf'{excel_IO.re.escape(package_name)}\b'

        if excel_IO.re.search(word_pattern, host, excel_IO.re.IGNORECASE):
            return
        

        # print(method, host)
        # print(f"path: {request.path}")
        
        contentType = ""
        contentLength = 0
        TransferEncoding = ""

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

                elif k.casefold() == "Transfer-Encoding".casefold():
                    TransferEncoding = v
                matched_patterns = excel_IO.match_prsnlList(prsnlList, (k, v), matched_patterns)


                if matched_patterns:
                    match = True
                    # return
                # elif matched_patterns == None:
                #     pass

       
        queries = request.query.items()
        if len(queries) > 0:

            for k, v in queries:
                matched_patterns = excel_IO.match_prsnlList(prsnlList, (k, v), matched_patterns)
                if matched_patterns:
                    match = True
                    # return
                # elif matched_patterns == None:
                #     return

        print (f"TransferEncoding: {TransferEncoding}")


        if  TransferEncoding == 'chunked' or contentLength > 0:

            text = request.get_text(False)

            print(type(text))  # <class 'NoneType'>

            # textformitmproxy = request.data.content  # bytes 형태로 데이터 추출

            content_encoding = request.headers.get("Content-Encoding", "")

            # 압축 해제 로직
            if "gzip" in content_encoding and not is_already_decoded(text):
                try:
                    compressed_data = BytesIO(text.encode('utf-8'))
                    with gzip.GzipFile(fileobj=compressed_data) as f:
                        text = f.read().decode('utf-8')
                        print('gzip 성공')
                        print(text)

                except (OSError, gzip.BadGzipFile) as e:
                    print('gzip 에러')
                    pass

            elif "deflate" in content_encoding and not is_already_decoded(text):
                try:
                    text = zlib.decompress(text.encode('utf-8')).decode('utf-8')
                except zlib.error as e:
                    pass
                
                
            try:
                # Content-Type에 따른 처리
                match contentType:
                    case "application/x-www-form-urlencoded":
                        data = parse_qs(text)
                        matched_patterns = excel_IO.match_prsnlList(prsnlList, data, matched_patterns)
                        print("x-www-form-urlencoded")

                        for k, v in data.items():
                            print(k)
                            print(v)
                        print('----------------------END--------------------')
                    case "application/json":
                        data = json.loads(text)
                        matched_patterns = excel_IO.match_prsnlList(prsnlList, data, matched_patterns)
                        print("json")

                    case "text/plain":
                        matched_patterns = excel_IO.match_prsnlList(prsnlList, text, matched_patterns)
                        print("text/plain")

                    case "application/octet-stream":
                        hex_data = text.encode('utf-8').hex()
                        print(f"Hexdump: {hex_data}")
                        matched_patterns = excel_IO.match_prsnlList(prsnlList, hex_data, matched_patterns)
                        print("octet-stream")

                    case _:
                        print(f"Unsupported Content-Type: {contentType}")
                        return

                # 매칭 결과 처리
                if matched_patterns:
                    match = True
                    print(match)
                elif matched_patterns is None:
                    print(matched_patterns)
                    return
                print('FALSE')
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

            print("\n----------------------\n")


            if len(headers) > 0:
                print("headers: [")
                for k, v in headers:
                    print(f"\t{k}: {v}")
                print("]")

            else:
                print("headers: []")


            if len(queries) > 0:
                print("queries: [")
                for k, v in queries:
                    print(f"\t{k}={v}")


                print(f"Query: {request.query}")
    
                print("]")
            else:
                print("queries: []")                

            print("\n----------------------\n")

            if method == "POST":
                process_post_request(request, contentType, contentLength, TransferEncoding)
            else:
                print("Not POST")
            
#--------------------------------------------------------------------------------------------------

            # 매칭된 데이터를 저장할 리스트
            data_to_write = []

            # 메소드와 호스트 추가
            data_to_write.append(method)
            data_to_write.append(host)

            data_to_write.append(f"path: {request.path}")


            # 헤더 추가
            headers = request.headers.items()
            if len(headers) > 0:
                data_to_write.append("headers: [")
                for k, v in headers:
                    data_to_write.append(f"{k}: {v}")
                data_to_write.append("]")

            else:
                data_to_write.append("headers: []")


                        # 쿼리 문자열 추가
            queries = request.query.items()
            if len(queries) > 0:
                data_to_write.append("queries: [")
                for k, v in queries:
                    data_to_write.append(f"{k}={v}")

                data_to_write.append("]")

            else:
                data_to_write.append("queries: []")       

            if method == "POST":
                process_post_request_excel(request, contentType, contentLength, data_to_write, TransferEncoding)
            else:
                pass

                     

            # 데이터를 엑셀에 기록
            excel_IO.write_to_excel(host, data_to_write, matched_patterns, package_name)


def process_post_request(request, contentType, contentLength, TransferEncoding):
    if  TransferEncoding == 'chunked' or contentLength > 0:
        try:
            print(f"=> {contentType}: [")
            text = request.get_text(False)

            # Content-Encoding 확인
            content_encoding = request.headers.get("Content-Encoding", "").lower()

            if "gzip" in content_encoding and not is_already_decoded(text):
                try:
                    compressed_data = BytesIO(text.encode('utf-8'))
                    with gzip.GzipFile(fileobj=compressed_data) as f:
                        text = f.read().decode('utf-8')
                except (OSError, gzip.BadGzipFile) as e:
                    print("Data is not gzipped as expected, processing as plain text.")

                except Exception as e:
                    print(f"Unexpected error while decompressing gzip: {e}")
                    
                    pass

            elif "deflate" in content_encoding and not is_already_decoded(text):
                try:
                    text = zlib.decompress(text.encode('utf-8')).decode('utf-8')
                except zlib.error as e:
                    print("Data is not deflated as expected, processing as plain text.")
                except Exception as e:
                    print(f"Unexpected error while decompressing deflate: {e}")
                    
                    pass



            match contentType:
                case "application/x-www-form-urlencoded":
                    data = parse_qs(text)
                    for k, v in data.items():
                        print(f"\t{k}={v}")

                case "application/json":
                    try:
                        data = json.loads(text)
                        print(json.dumps(data, indent=4))
                    except json.JSONDecodeError as e:
                        print("Failed to decode JSON:", e)

                case "text/plain":
                    print(text)

                case "application/octet-stream":
                    hex_data = text.encode('utf-8').hex()
                    print(f"Hexdump: {hex_data}")

                case _:
                    print("\t** SKIP **")

            print("]")
        except Exception as e:
            print(f"An error occurred: {e}")
            print("Processing as plain text:", text)

        print("\033[93m" + "어떤 내용이 있다" + "\033[0m")
        return True
    else:
        print("\033[93m" + "POST이긴 하다" + "\033[0m")


def process_post_request_excel(request, contentType, contentLength, data_to_write , TransferEncoding):
    if  TransferEncoding == 'chunked' or contentLength > 0:
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
            content_encoding = request.headers.get("Content-Encoding", "")

            # gzip 또는 deflate 압축 해제 시도
            if "gzip" in content_encoding and not is_already_decoded(text):
                try:
                    compressed_data = BytesIO(text.encode('utf-8'))
                    with gzip.GzipFile(fileobj=compressed_data) as f:
                        decompressed_data = f.read().decode('utf-8')
                    text = decompressed_data
                except gzip.BadGzipFile:
                    print("Error: Data is not gzipped as expected, processing as plain text.")
                except Exception as e:
                    print(f"Unexpected error while decompressing gzip: {e}")

            elif "deflate" in content_encoding and not is_already_decoded(text):
                try:
                    decompressed_data = zlib.decompress(text.encode('utf-8')).decode('utf-8')
                    text = decompressed_data
                except zlib.error as e:
                    print(f"Error while decompressing deflate: {e}")
                except Exception as e:
                    print(f"Unexpected error while decompressing deflate: {e}")

            # Content-Type에 따라 데이터 처리
            match contentType:
                case "application/x-www-form-urlencoded":
                    data = parse_qs(text)
                    for k, v in data.items():
                        escaped_key = escape_excel_formula(k)
                        escaped_value = escape_excel_formula(v)
                        data_to_write.append(f"\t{escaped_key}={escaped_value}")

                case "application/json":
                    try:
                        data = json.loads(text)
                        if isinstance(data, dict):
                            for k, v in data.items():
                                escaped_key = escape_excel_formula(k)
                                escaped_value = escape_excel_formula(v)
                                data_to_write.append(f"\t{escaped_key}: {escaped_value}")
                        elif isinstance(data, list):
                            for i, item in enumerate(data):
                                escaped_item = escape_excel_formula(item)
                                data_to_write.append(f"\t{i}: {escaped_item}")
                    except json.JSONDecodeError as e:
                        print(f"JSON Decode Error: {e}")
                        print("Invalid JSON:", text)

                case "text/plain":
                    escaped_text = escape_excel_formula(text)
                    data_to_write.append(f"\t{escaped_text}")

                case "application/octet-stream":
                    # Binary data processing, here we just store the hexdump
                    hex_data = text.encode('utf-8').hex()
                    data_to_write.append(f"\tHexdump: {hex_data}")

                case _:
                    data_to_write.append("\t** SKIP **")

            data_to_write.append("]")  # 데이터의 끝에 닫는 대괄호 추가
        except Exception as e:
            print(f"An error occurred: {e}")
            print("Processing as plain text:", text)
    else:
        data_to_write.append("post contents 없음")


def is_already_decoded(data):
    """
    데이터가 이미 압축 해제된 상태인지 확인합니다.
    
    :param data: 검사할 텍스트 데이터
    :return: True이면 이미 압축 해제된 상태, False이면 압축된 상태
    """
    # 바이트 형식으로 변환
    data_bytes = data.encode('utf-8')
    
    # Gzip 매직 넘버 검사 (첫 2바이트가 0x1f 0x8b인지 확인)
    if len(data_bytes) >= 2 and data_bytes[:2] == b'\x1f\x8b':
        return False  # 압축된 데이터
    
    # 기타 압축 형식 (예: Deflate) 검사 - Deflate는 명확한 매직 넘버가 없으므로 추가 검사 불가능
    # 보통 Gzip만 체크하고 나머지는 압축되지 않은 상태로 간주하는 것이 일반적입니다.
    
    return True  # 이미 압축 해제된 데이터로 간주

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
