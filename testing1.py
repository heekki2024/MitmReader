class MyContextManager:
    def __enter__(self):
        print("Entering the context")
        # 리소스를 열거나 준비할 때 필요한 작업을 여기에 작성
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # 리소스를 닫거나 정리할 때 필요한 작업을 여기에 작성
        print("Exiting the context")
        if exc_type is not None:
            print(f"An exception occurred: {exc_value}")
        # 예외가 처리되었는지를 나타내기 위해 True 또는 False를 반환
        return True  # True를 반환하면 예외가 상위로 전달되지 않음

# 사용 예제
with MyContextManager() as manager:
    print("Inside the context")
    raise ValueError("Something went wrong")  # 예외 발생