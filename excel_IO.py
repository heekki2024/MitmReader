import openpyxl
import re
import os
from openpyxl.utils.exceptions import IllegalCharacterError

MAX_HOSTNAME_LENGTH = 31

def excel_trackerList_input():
    trackerList_path = r"C:\Users\xten\Desktop\goodchoicetracker.xlsx"
    wb = openpyxl.load_workbook(trackerList_path)
    ws = wb['Sheet1']
    if 'Sheet1' in wb.sheetnames:
        last_row = ws.max_row
        trackerList = []
        for i in range(1, last_row + 1, 1):
            trackerList.append(ws[f'A{i}'].value)
    return trackerList

def excel_prsnlList_input():
    prsnlList_path = r"C:\Users\xten\Desktop\prsnlList.xlsx"
    wb = openpyxl.load_workbook(prsnlList_path)
    ws = wb['Sheet1']
    if 'Sheet1' in wb.sheetnames:
        last_row = ws.max_row
        prsnlList = []
        for i in range(1, last_row + 1, 1):
            prsnlList.append(ws[f'A{i}'].value)        
    return prsnlList




def match_trackerList(trackerList, host):
    for pattern in trackerList:
        # trackerList의 각 항목을 단어로 검색하기 위해 단어 경계(\b)를 추가
        word_pattern = rf'{re.escape(pattern)}\b'
        if re.search(word_pattern, host, re.IGNORECASE):
            return True
    return False


def match_prsnlList(prsnlList, kv):

    if isinstance(kv, list):
        for k, v in kv:
            for pattern in prsnlList:
                if pattern is None:  # None 무시
                    continue
                word_pattern = rf'{re.escape(str(pattern))}\b'  # 패턴을 문자열로 변환
                if re.search(word_pattern, k, re.IGNORECASE) or re.search(word_pattern, v, re.IGNORECASE):

                    return True

    elif isinstance(kv, tuple) and len(kv) == 2:
        k, v = kv
        for pattern in prsnlList:
            if pattern is None:  # None 무시
                continue
            word_pattern = rf'{re.escape(str(pattern))}\b'  # 패턴을 문자열로 변환
            if re.search(word_pattern, k, re.IGNORECASE) or re.search(word_pattern, v, re.IGNORECASE):

                return True
                
    elif isinstance(kv, str):
        for pattern in prsnlList:
            if pattern is None:  # None 무시
                continue
            word_pattern = rf'{re.escape(str(pattern))}\b'  # 패턴을 문자열로 변환
            if re.search(word_pattern, kv, re.IGNORECASE):

                return True
                
    return False

# 엑셀 파일 경로 설정
excel_file_path = r"C:\Users\kfri1\Desktop\231output.xlsx"

def clean_host_name(host):
    """
    호스트 이름을 Excel 시트 이름으로 사용할 수 있도록 수정합니다.
    길이를 31자로 제한하고 특수 문자를 제거합니다.
    """
    # 특수 문자 제거
    clean_host = re.sub(r'[\/:*?"<>|]', '', host)
    
    # 길이 제한
    if len(clean_host) > MAX_HOSTNAME_LENGTH:
        clean_host = clean_host[:MAX_HOSTNAME_LENGTH]
    
    return clean_host

def clean_string(value):
    # 허용되지 않는 제어 문자를 제거
    return re.sub(r'[\x00-\x1F\x7F]', '', value)

def write_to_excel(host, data, package_name):

    results_folder_path = r"C:\Users\xten\Desktop\testing1"
    result_path = os.path.join(results_folder_path, f"{package_name}.xlsx")

    if os.path.exists(result_path):
        wb = openpyxl.load_workbook(result_path)
    else:
        wb = openpyxl.Workbook()

        # 기본으로 생성되는 'Sheet' 시트를 제거
        default_sheet = wb.active
        wb.remove(default_sheet)

    clean_host = clean_host_name(host)

    if clean_host in wb.sheetnames:
        ws = wb[clean_host]
    else:
        ws = wb.create_sheet(title=clean_host)
    # 현재 마지막 열을 찾기
    last_column = ws.max_column
    if last_column == 1 and ws.cell(row=1, column=1).value is None:
        last_column = 0

    # 새로운 열에서 데이터 입력 시작
    start_column = last_column + 1
    for i, value in enumerate(data, start=1):
        try:
            cleaned_value = clean_string(value)
            ws.cell(row=i, column=start_column, value=cleaned_value)
        except IllegalCharacterError as e:
            print(f"Illegal character in value: {value}. Error: {e}") 

    try:
        wb.save(result_path)
    except Exception as e:
        print(f"Error saving Excel file: {e}")

