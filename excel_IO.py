import openpyxl
import re


def excel_trackerList_input():
    trackerList_path = r"C:\Users\xten\Desktop\trackList.xlsx"
    wb = openpyxl.load_workbook(trackerList_path)
    ws = wb['Sheet1']
    if 'Sheet1' in wb.sheetnames:
        last_row = ws.max_row
        trackerList = []
        for i in range(1, last_row + 1, 1):
            trackerList.append(ws[f'A{i}'].value)
    return trackerList

def excel_prsnlList_input():
    prsnlList_path = r"C:\Users\xten\Desktop\trackList.xlsx"
    wb = openpyxl.load_workbook(prsnlList_path)
    ws = wb['Sheet1']
    if 'Sheet1' in wb.sheetnames:
        last_row = ws.max_row
        print(last_row)
        prsnlList = []
        for i in range(1, last_row + 1, 1):
            prsnlList.append(ws[f'A{i}'].value)        
    return prsnlList

count = 0

# def match_trackerList(trackerList, host):
#     for pattern in trackerList:
#         # trackerList에 있는 항목이 host와 부분적으로 일치하는지 확인
#         if re.search(pattern, host, re.IGNORECASE):
#             global count
#             count+=1
#             print(count)
#             return True,count
#     return False

def match_trackerList(trackerList, host):
    for pattern in trackerList:
        # trackerList의 각 항목을 단어로 검색하기 위해 단어 경계(\b)를 추가
        word_pattern = rf'\b{re.escape(pattern)}\b'
        if re.search(word_pattern, host, re.IGNORECASE):
            global count
            count+=1
            print(count)
            return True
    return False

# def match_trackerList(trackerList, host):

#         for i in range(len(trackerList)):
#             if host == trackerList[i]:
#                 global count
#                 count+=1
#                 print(count)
#                 return True
#         return False  


# def match_prsnlList():

