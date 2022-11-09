import pandas as pd

FILES_PATH = '../Data/CIC-IDS2017/'
FILE_NAME_LIST = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
]


def read_file(file_path):
    return pd.read_csv(file_path, encoding="utf-8")


def process_datetime(file_df):
    dt_lst = file_df[' Timestamp'].tolist()
    dt_df = pd.to_datetime(dt_lst)
    for i in range(len(dt_lst)):
       dt_lst[i] =  dt_df[i].hour * 60 + dt_df[i].minute

    file_df[' Timestamp'] = pd.DataFrame(dt_lst)
    return file_df


def process_all_date(file_df):
    x = file_df[' Timestamp'].tolist()
    for i in range(len(x)):
        # x[i] = (int(x[i].split(' ')[1].split(':')[0]) + 12) * 60 + int(x[i].split(' ')[1].split(':')[1])
        x[i] = int(x[i].split(' ')[1].split(':')[0]) * 60 + int(x[i].split(' ')[1].split(':')[1])
    file_df[' Timestamp'] = pd.DataFrame(x)
    return file_df


def process_data_with_threshold(file_df):
    threshold = 1
    x = file_df[' Timestamp'].tolist()
    for i in range(len(x)):
        temp = int(x[i].split(' ')[1].split(':')[0])
        temp1 = int(x[i].split(' ')[1].split(':')[1])
        # print(temp)
        if temp == (threshold + 1):
            threshold += 1
        if temp <= threshold:
            x[i] = (temp + 12) * 60 + temp1
        else:
            x[i] = temp * 60 + temp1
    file_df[' Timestamp'] = pd.DataFrame(x)
    return file_df


if __name__ == '__main__':

    for i in FILE_NAME_LIST:
        file_df = read_file(FILES_PATH + i)
        file_df = process_datetime(file_df)
        file_df.to_csv(FILES_PATH + i)







