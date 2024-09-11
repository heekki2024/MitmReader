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
import base64
from email.parser import BytesParser
from email.policy import default
import cgi
import binascii



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







#------------------------------------------------------------------------------------------
def process_request_personInfo(f, total_prsnlList, wb, hostlist, key_prsnlList, value_prsnlList, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count, app_name):
    global match
    matched_patterns = []
    data_to_write = []


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

        # data_to_write.append(request)
        data_to_write.append(method)
        data_to_write.append(host)

        # word_pattern = rf'{excel_IO.re.escape(package_name)}\b'

        # if excel_IO.re.search(word_pattern, host, excel_IO.re.IGNORECASE):
        #     return
        

        # print(method, host)
        # print(f"path: {request.path}")
        
        contentType = ""
        contentLength = 0
        TransferEncoding = ""

        headers = request.headers.items()
        if len(headers) > 0:
            data_to_write.append("headers: [")
            # print("headers: [")
            for k, v in headers:
                # print(f"\t{k}: {v}")
                if k.casefold() == "Content-Type".casefold():
                    vv = v.split(";")
                    contentType = vv[0]
                    boundary_kv = v.split("boundary=")[-1]


                elif k.casefold() == "Content-Length".casefold():
                    contentLength = int(v)

                elif k.casefold() == "Transfer-Encoding".casefold():
                    TransferEncoding = v  

    
                matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, (k, v), matched_patterns, data_to_write)


                if matched_patterns:
                    match = True
                    # return
                elif matched_patterns == None:
                    return hostlist, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count

            data_to_write.append("]")

        else:
            data_to_write.append("headers: []")
 


        queries = request.query.items()
        if len(queries) > 0:
            data_to_write.append("queries:[")
            for k, v in queries:
                matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, (k, v), matched_patterns, data_to_write)
                if matched_patterns:
                    match = True
                    # return
                # elif matched_patterns == None:
                #     return

            data_to_write.append("]")
        else:
            data_to_write.append("queries: []")

        print (f"TransferEncoding: {TransferEncoding}")


        if  TransferEncoding == 'chunked' or contentLength > 0:

            data_to_write.append(f"-> {contentType}: [")

            text = request.get_text(False)

            print(type(text))  # <class 'NoneType'>

            # textformitmproxy = request.data.content  # bytes 형태로 데이터 추출

            content_encoding = request.headers.get("Content-Encoding", "")

            # # 압축 해제 로직
            # if "gzip" in content_encoding and not is_already_decoded(text):
            #     try:
            #         compressed_data = BytesIO(text.encode('utf-8'))
            #         with gzip.GzipFile(fileobj=compressed_data) as f:
            #             text = f.read().decode('utf-8')
            #             print('gzip 성공')
            #             print(text)

            #     except (OSError, gzip.BadGzipFile) as e:
            #         print('gzip 에러')
            #         pass

            # elif "deflate" in content_encoding and not is_already_decoded(text):
            #     try:
            #         text = zlib.decompress(text.encode('utf-8')).decode('utf-8')
            #     except zlib.error as e:
            #         pass
                
            # 압축 해제 로직
            if "gzip" in content_encoding and not is_already_decoded(text):
                try:
                    # text가 바이너리 데이터로 가정
                    compressed_data = BytesIO(text)
                    with gzip.GzipFile(fileobj=compressed_data) as f:
                        text = f.read().decode('utf-8')
                        print('gzip 성공')
                        print(text)

                except (OSError, gzip.BadGzipFile) as e:
                    print('gzip 에러:', e)

            elif "deflate" in content_encoding and not is_already_decoded(text):
                try:
                    # text가 바이너리 데이터로 가정
                    text = zlib.decompress(text).decode('utf-8')
                    print('deflate 성공')
                except zlib.error as e:
                    print('deflate 에러:', e)                


            try:
                # Content-Type에 따른 처리
                match contentType:
                    case "application/x-www-form-urlencoded":
                        data = parse_qs(text)
                        matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, data, matched_patterns, data_to_write)
                        print("x-www-form-urlencoded")

                        # for k, v in data.items():
                        #     print(k)
                        #     print(v)
                        # print('----------------------END--------------------')
                    case "application/json":
                        data = json.loads(text)
                        matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, data, matched_patterns, data_to_write)
                        print("json")

                    case "text/plain":
                        matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, text, matched_patterns, data_to_write)
                        print("text/plain")

                    case "application/octet-stream":
                        hex_data = text.encode('utf-8').hex()
                        print(f"Hexdump: {hex_data}")
                        matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, hex_data, matched_patterns, data_to_write)
                        print("octet-stream")

                    case "application/x-ndjson":    
                        raw_lines = text.splitlines()
                        for line in raw_lines:                            
                            json_object = json.loads(line)
                            # print(json.dumps(json_object, indent=4))  # JSON 객체 출력
                            matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, json_object, matched_patterns, data_to_write)
                            print("x-ndjson")
                    case "application/x-amz-json-1.0":
                        # Kinesis 요청 본문은 Base64로 인코딩된 Data 필드를 포함
                        json_data = json.loads(text)
                        # for record in json_data['Records']:
                        #     decoded_data = base64.b64decode(record['Data']).decode('utf-8')
                        #     print(f"Decoded Kinesis Data: {decoded_data}")
                        matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, json_data, matched_patterns, data_to_write)
                        print("application/x-amz-json-1.1")                            

                    case "application/x-amz-json-1.1":
                        # Kinesis 요청 본문은 Base64로 인코딩된 Data 필드를 포함
                        json_data = json.loads(text)
                        # for record in json_data['Records']:
                        #     decoded_data = base64.b64decode(record['Data']).decode('utf-8')
                        #     print(f"Decoded Kinesis Data: {decoded_data}")
                        matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, json_data, matched_patterns, data_to_write)
                        print("application/x-amz-json-1.1")

                    case "multipart/form-data":
                        # boundary 파싱 (boundary 문자열 추출)
                        boundary = boundary_kv.split("boundary=")[-1]
                        # multipart 데이터 파싱
                        parsed_data = cgi.parse_multipart(BytesIO(text.encode('utf-8')), {"boundary": boundary.encode('utf-8')})

                        # protobuf 데이터 처리
                        if "input_protobuf_encoded" in parsed_data:
                            protobuf_encoded = parsed_data['input_protobuf_encoded'][0]
                            try:
                                decoded_protobuf = base64.b64decode(protobuf_encoded)
                                print("multipart/form-data")

                                # protobuf로 디코딩된 데이터를 필요한 방식으로 처리
                                # 예를 들어 excel_IO.match_prsnlList와 같은 함수로 데이터를 처리
                                matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, decoded_protobuf, matched_patterns, data_to_write)
                            except (base64.binascii.Error, UnicodeDecodeError) as e:
                                print(f"Protobuf 디코딩 에러: {e}")
                                return None                        

                    case "application/binary":

                        # 문자열을 bytes로 변환 (utf-8 인코딩 사용)
                        binary_data = text.encode('utf-8')
                        
                        # bytes 데이터를 헥사 문자열로 변환
                        hex_data = binascii.hexlify(binary_data).decode('ascii')
                        matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, hex_data, matched_patterns, data_to_write)
                        print("application/binary")
                    case "application/x-protobuf":
                        if isinstance(text, str):
                            text = text.encode('utf-8')
                        # Protobuf 데이터를 읽기 위해 BytesIO 객체로 변환
                        binary_data = BytesIO(text)
                        matched_patterns, data_to_write = excel_IO.match_prsnlList(total_prsnlList, binary_data.getvalue(), matched_patterns, data_to_write)
                        print("application/x-protobuf")

                    case _:
                        print(f"Unsupported Content-Type: {contentType}")
                        raise
                data_to_write.append(f"]")

                # 매칭 결과 처리
                if matched_patterns:
                    match = True
                    print(match)
                elif matched_patterns is None:
                    print(matched_patterns)
                    return hostlist, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count

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
                process_post_request(request, contentType, contentLength, TransferEncoding, boundary_kv=None)
            else:
                print("Not POST")
            
#--------------------------------------------------------------------------------------------------

            print(matched_patterns)
            matched_patterns_set = set(matched_patterns)     
            no_dup_matched_patterns = list(matched_patterns_set)
            print(no_dup_matched_patterns)
            no_dup_matched_patterns_to_write = []

            no_dup_matched_patterns_to_write.append("발견된 값: [")

            for item in no_dup_matched_patterns:
                no_dup_matched_patterns_to_write.append(item)

            no_dup_matched_patterns_to_write.append("]")
       

            # 데이터를 엑셀에 기록
            excel_IO.write_to_excel(host, data_to_write, total_prsnlList, no_dup_matched_patterns_to_write, wb)
            hostlist, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count= excel_IO.write_Result(host, hostlist, wb, key_prsnlList, value_prsnlList, no_dup_matched_patterns, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count, app_name)
    return hostlist, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count

def process_post_request(request, contentType, contentLength, TransferEncoding, boundary_kv):
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

                case "application/x-ndjson":    
                    raw_lines = text.splitlines()
                    for line in raw_lines:                            
                        json_object = json.loads(line)
                        print(json.dumps(json_object, indent=4))  # JSON 객체 출력
                case "application/x-amz-json-1.0":
                    # Kinesis 요청 본문은 Base64로 인코딩된 Data 필드를 포함
                    json_data = json.loads(text)
                    for record in json_data['Records']:
                        # decoded_data = base64.b64decode(record['Data']).decode('utf-8')
                        print(f"Decoded Kinesis Data: {record}")


                case "application/x-amz-json-1.1":
                    # Kinesis 요청 본문은 Base64로 인코딩된 Data 필드를 포함
                    json_data = json.loads(text)
                    for record in json_data['Records']:
                        # decoded_data = base64.b64decode(record['Data']).decode('utf-8')
                        print(f"Decoded Kinesis Data: {record}")

                case "multipart/form-data":
                    # boundary 파싱 (boundary 문자열 추출)
                    boundary = boundary_kv.split("boundary=")[-1]
                    # multipart 데이터 파싱
                    parsed_data = cgi.parse_multipart(BytesIO(text.encode('utf-8')), {"boundary": boundary.encode('utf-8')})

                    # protobuf 데이터 처리
                    if "input_protobuf_encoded" in parsed_data:
                        protobuf_encoded = parsed_data['input_protobuf_encoded'][0]
                        try:
                            decoded_protobuf = base64.b64decode(protobuf_encoded)
                            print(f"Decoded Protobuf Data: {decoded_protobuf}")

                            # protobuf로 디코딩된 데이터를 필요한 방식으로 처리
                            # 예를 들어 excel_IO.match_prsnlList와 같은 함수로 데이터를 처리
                        except (base64.binascii.Error, UnicodeDecodeError) as e:
                            print(f"Protobuf 디코딩 에러: {e}")
                            return None
                case "application/binary":

                    # 문자열을 bytes로 변환 (utf-8 인코딩 사용)
                    binary_data = text.encode('utf-8')
                    
                    # bytes 데이터를 헥사 문자열로 변환
                    hex_data = binascii.hexlify(binary_data).decode('ascii')
                    print("Hex Data:", hex_data)

                case "application/x-protobuf":

                    if isinstance(text, str):
                        text = text.encode('utf-8')
                    # Protobuf 데이터를 읽기 위해 BytesIO 객체로 변환
                    binary_data = BytesIO(text)
                    
                    # 원시 데이터를 출력
                    print("Raw Protobuf Data:", binary_data.getvalue())
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
    app_name = os.path.basename(dump_path)

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
                hostlist = []
                row_hostlist_number = 2
                hostlist_number_dict = {}
                hostlist_etc_dict = {}
                hostlist_count = 1
                

                total_prsnlList, key_prsnlList, value_prsnlList = excel_IO.excel_prsnlList_input()
                wb, result_path = excel_IO.open_excel(app_name, key_prsnlList)

                for f in freader.stream():
                    global match
                    


                    hostlist, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count = process_request_personInfo(f, total_prsnlList, wb, hostlist, key_prsnlList, value_prsnlList, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count, app_name)
                    # excel_IO.making_Result(host, hostlist)

                    print("")
                    match = False
                    totcount += 1
                    print(f"\033[94m" + "total count" + str({totcount}) + "\033[0m")

                    print("\n!===============================!\n")

            elif mode == '3':
                totcount = 0
                hostlist = []
                row_hostlist_number = 2
                hostlist_number_dict = {}
                hostlist_etc_dict = {}
                hostlist_count = 1
                

                
                total_prsnlList, key_prsnlList, value_prsnlList = excel_IO.excel_prsnlList_input()
                wb, result_path = excel_IO.open_excel(app_name, key_prsnlList)

                for f in freader.stream():
                    global match
                    


                    hostlist, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count = process_request_personInfo(f, total_prsnlList, wb, hostlist, key_prsnlList, value_prsnlList, row_hostlist_number, hostlist_number_dict, hostlist_etc_dict, hostlist_count, app_name)
                    # excel_IO.making_Result(host, hostlist)

                    print("")
                    match = False
                    totcount += 1
                    print(f"\033[94m" + "total count" + str({totcount}) + "\033[0m")

                    print("\n!===============================!\n")                    

                try:
                    wb.save(result_path)
                except Exception as e:
                    print(f"Error saving Excel file: {e}")
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
