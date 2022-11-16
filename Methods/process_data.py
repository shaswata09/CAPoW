import pandas as pd
import os

from enum import Enum

FILES_PATH = '../Data/CIC-IDS2017/'
FILE_NAME_LIST = [
    [
        'Monday-WorkingHours.pcap_ISCX.csv'
    ],
    [
        'Tuesday-WorkingHours.pcap_ISCX.csv'
    ],
    [
        'Wednesday-workingHours.pcap_ISCX.csv'
    ],
    [
        'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
    ],
    [
        'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
    ]
]

ALL_COLUMNS = [
    'Flow ID',
    ' Source IP',
    ' Source Port',
    ' Destination IP',
    ' Destination Port',
    ' Protocol',
    ' Timestamp',
    ' Flow Duration',
    ' Total Fwd Packets',
    ' Total Backward Packets',
    'Total Length of Fwd Packets',
    ' Total Length of Bwd Packets',
    ' Fwd Packet Length Max',
    ' Fwd Packet Length Min',
    ' Fwd Packet Length Mean',
    ' Fwd Packet Length Std',
    'Bwd Packet Length Max',
    ' Bwd Packet Length Min',
    ' Bwd Packet Length Mean',
    ' Bwd Packet Length Std',
    'Flow Bytes/s',
    ' Flow Packets/s',
    ' Flow IAT Mean',
    ' Flow IAT Std',
    ' Flow IAT Max',
    ' Flow IAT Min',
    'Fwd IAT Total',
    ' Fwd IAT Mean',
    ' Fwd IAT Std',
    ' Fwd IAT Max',
    ' Fwd IAT Min',
    'Bwd IAT Total',
    ' Bwd IAT Mean',
    ' Bwd IAT Std',
    ' Bwd IAT Max',
    ' Bwd IAT Min',
    'Fwd PSH Flags',
    ' Bwd PSH Flags',
    ' Fwd URG Flags',
    ' Bwd URG Flags',
    ' Fwd Header Length',
    ' Bwd Header Length',
    'Fwd Packets/s',
    ' Bwd Packets/s',
    ' Min Packet Length',
    ' Max Packet Length',
    ' Packet Length Mean',
    ' Packet Length Std',
    ' Packet Length Variance',
    'FIN Flag Count',
    ' SYN Flag Count',
    ' RST Flag Count',
    ' PSH Flag Count',
    ' ACK Flag Count',
    ' URG Flag Count',
    ' CWE Flag Count',
    ' ECE Flag Count',
    ' Down/Up Ratio',
    ' Average Packet Size',
    ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size',
    ' Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk',
    ' Fwd Avg Packets/Bulk',
    ' Fwd Avg Bulk Rate',
    ' Bwd Avg Bytes/Bulk',
    ' Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets',
    ' Subflow Fwd Bytes',
    ' Subflow Bwd Packets',
    ' Subflow Bwd Bytes',
    'Init_Win_bytes_forward',
    ' Init_Win_bytes_backward',
    ' act_data_pkt_fwd',
    ' min_seg_size_forward',
    'Active Mean',
    ' Active Std',
    ' Active Max',
    ' Active Min',
    'Idle Mean',
    ' Idle Std',
    ' Idle Max',
    ' Idle Min',
    ' Label',
]

DROP_COLUMNS = [
    'Flow ID',
    ' Subflow Bwd Packets',
    'Idle Mean',
    ' Flow Packets/s',
    ' Flow Duration',
    ' Total Backward Packets',
    ' min_seg_size_forward',
    ' Fwd Packet Length Std',
    ' Fwd IAT Std',
    ' Flow IAT Std',
    ' Flow IAT Max',
    'Subflow Fwd Packets',
    ' Fwd IAT Max',
    ' Idle Min',
    ' Total Fwd Packets',
    ' Fwd Header Length',
    ' Fwd Header Length.1',
    ' Max Packet Length',
    ' Total Length of Bwd Packets',
    ' Bwd Packet Length Std',
    ' Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Total Length of Fwd Packets',
    ' Bwd Packet Length Mean',
    ' Packet Length Mean',
    ' Avg Bwd Segment Size',
    ' Average Packet Size',
    ' Label'
]

TIME_FILTRATION_COL = [
    ' Source IP',
    ' Timestamp'
]

# DATA_TYPE = Enum('DATA_TYPE', ['BENIGN', 'MALICIOUS'])
class DATA_TYPE(Enum):
    BENIGN = 'BENIGN'
    MALICIOUS = 'MALICIOUS'

class ProcessData:
    def read_file(file_path: str):
        return pd.read_csv(file_path)

    def filter_benign_data(file_df: pd.DataFrame):
        return file_df[file_df[' Label'] == 'BENIGN']

    def filter_malicious_data(file_df: pd.DataFrame):
        return file_df[file_df[' Label'] != 'BENIGN']

    def filter_columns(file_df: pd.DataFrame):
        return file_df.drop(DROP_COLUMNS, axis=1)

    def get_processed_df(file_path: str, type: str = DATA_TYPE.BENIGN):
        file_df = ProcessData.read_file(file_path)
        if type == DATA_TYPE.BENIGN:
            file_df = ProcessData.filter_benign_data(file_df)
        else:
            file_df = ProcessData.filter_malicious_data(file_df)
        file_df = ProcessData.filter_columns(file_df)
        return file_df

    def get_time_data(file_df: pd.DataFrame):
        for i in file_df.columns:
            if i not in TIME_FILTRATION_COL:
                file_df = file_df.drop(i, axis=1)
        return file_df

    def get_file_by_day(day: int, type: str = DATA_TYPE.BENIGN):
        file_df = ProcessData.get_processed_df(FILES_PATH + FILE_NAME_LIST[day][0], type)
        for i in FILE_NAME_LIST[day][1:]:
            file_df = pd.concat([file_df, ProcessData.get_processed_df(FILES_PATH + i, type)], axis=0)
        return file_df


if __name__ == '__main__':
    file_df = ProcessData.read_file(os.path.join(FILES_PATH + FILE_NAME_LIST[2][0]))
    print(file_df.shape)
    file_df = ProcessData.get_file_by_day(2)
    print(file_df.shape)

    # # To test an ip in the dataframe
    # temp = file_df.loc[file_df[' Source IP'] == '64.71.142.124']
    # print(temp)
