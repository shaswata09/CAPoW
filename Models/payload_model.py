import pandas as pd
import pickle


from Methods.process_data import ProcessData
from Methods.process_data import DATA_TYPE

PAYLOAD_FILTRATION_COL = [
    'Total Length of Fwd Packets',
    ' Total Length of Bwd Packets',
    ' Bwd Packet Length Mean',
    ' Fwd Header Length',
    ' Average Packet Size',
    ' Avg Bwd Segment Size',
    ' Fwd Header Length.1',
    ' Subflow Fwd Bytes',
    ' Subflow Bwd Bytes'
]

# PAYLOAD_FILTRATION_COL = [
#     ' Flow Duration',
#     ' Total Fwd Packets',
#     ' Total Backward Packets',
#     'Total Length of Fwd Packets',
#     ' Total Length of Bwd Packets',
#     ' Fwd Packet Length Max',
#     ' Fwd Packet Length Min',
#     ' Fwd Packet Length Mean',
#     ' Fwd Packet Length Std',
#     'Bwd Packet Length Max',
#     ' Bwd Packet Length Min',
#     ' Bwd Packet Length Mean',
#     ' Bwd Packet Length Std',
#     'Flow Bytes/s',
#     ' Flow Packets/s',
#     ' Flow IAT Mean',
#     ' Flow IAT Std',
#     ' Flow IAT Max',
#     ' Flow IAT Min',
#     'Fwd IAT Total',
#     ' Fwd IAT Mean',
#     ' Fwd IAT Std',
#     ' Fwd IAT Max',
#     ' Fwd IAT Min',
#     'Bwd IAT Total',
#     ' Bwd IAT Mean',
#     ' Bwd IAT Std',
#     ' Bwd IAT Max',
#     ' Bwd IAT Min',
#     ' Fwd Header Length',
#     ' Bwd Header Length',
#     'Fwd Packets/s',
#     ' Bwd Packets/s',
#     ' Min Packet Length',
#     ' Max Packet Length',
#     ' Packet Length Mean',
#     ' Packet Length Std',
#     ' Packet Length Variance',
#     ' Down/Up Ratio',
#     ' Average Packet Size',
#     ' Avg Fwd Segment Size',
#     ' Avg Bwd Segment Size',
#     ' Fwd Header Length.1',
#     'Subflow Fwd Packets',
#     ' Subflow Fwd Bytes',
#     ' Subflow Bwd Packets',
#     ' Subflow Bwd Bytes',
#     'Init_Win_bytes_forward',
#     ' Init_Win_bytes_backward',
#     ' act_data_pkt_fwd',
#     ' min_seg_size_forward'
# ]

payload_cluster_origins = {
    DATA_TYPE.BENIGN: {},
    DATA_TYPE.MALICIOUS: {}
}

PROCESSED_FILES_PATH = '../Data/Processed-CIC-IDS2017/'
PAYLOAD_CLUSTER_ORIGINS_FILE_NAME = 'payload_cluster_origins.pkl'

"""
payload_cluster_origins Data Structure

payload_cluster_origins = {
    'BENIGN': {
        'attribute1': value,
        'attribute2': value,
        ...
    },
    'MALICIOUS': {
        'attribute1': value,
        'attribute2': value,
        ...
    }
}
"""

class PayloadModel:
    def read_cluster_origins(file_path: str):
        with open(file_path, 'rb') as f:
            payload_cluster_origins = pickle.load(f)
        return payload_cluster_origins

    def save_cluster_origins(file_path: str, payload_cluster_origins: dict):
        with open(file_path, 'wb') as f:
            pickle.dump(payload_cluster_origins, f)
            print(f"Successfully saved at: {file_path}")

    def generate_cluster_center(file_df: pd.DataFrame):
        origin_dict = {}
        for column in file_df.columns:
            origin = 0
            for index, row in file_df.iterrows():
                origin += row[column]
            origin /= file_df.shape[0]
            origin_dict[column] = origin
        return origin_dict

    def split_train_test(file_df: pd.DataFrame, test_frac: float = 0.05):
        test_file_df = file_df.sample(frac = test_frac)
        train_file_df = file_df.drop(test_file_df.index)
        return train_file_df, test_file_df

    def generate_cluster_origins(file_df: pd.DataFrame, type: str = DATA_TYPE.BENIGN):
        origin_dict = PayloadModel.generate_cluster_center(file_df)
        payload_cluster_origins[type] = origin_dict

    def generate_payload_cluster(type: str = DATA_TYPE.BENIGN):
        file_df = ProcessData.get_file_by_day(0, type, False)
        for i in range(1, 5):
            file_df = pd.concat([file_df, ProcessData.get_file_by_day(i, type, False)], axis=0)

        file_df = ProcessData.get_payload_data(file_df, PAYLOAD_FILTRATION_COL)
        train_file_df, test_file_df = PayloadModel.split_train_test(file_df, 0.05)

        return train_file_df, test_file_df

    def get_test_set(benign_test_file_df: pd.DataFrame, malicious_test_file_df: pd.DataFrame):
        return pd.concat([benign_test_file_df, malicious_test_file_df], axis=0)

    def get_reputation_score(value_dict: dict):
        benign_dist = 0
        malicious_dist = 0
        for col in value_dict.keys():
            try:
                benign_dist += ((payload_cluster_origins[DATA_TYPE.BENIGN][col] - value_dict[col]) ** 2)
                malicious_dist += ((payload_cluster_origins[DATA_TYPE.MALICIOUS][col] - value_dict[col]) ** 2)
            except:
                print(col)
                print(payload_cluster_origins[DATA_TYPE.BENIGN][col])
                print(value_dict[col])

        benign_dist = benign_dist ** (0.5)
        malicious_dist = malicious_dist ** (0.5)
        return (benign_dist/(benign_dist+malicious_dist))*10

    def test_accuracy(file_df: pd.DataFrame):
        benign_count = 0
        malicious_count = 0
        for index, row in file_df.iterrows():
            test_value = {}
            for column in file_df.columns:
                test_value[column] = row[column]
            score = PayloadModel.get_reputation_score(test_value)
            if score > 5:
                malicious_count += 1
            else:
                benign_count += 1

        print(f"benign_count: {benign_count}")
        print(f"malicious_count: {malicious_count}")


if __name__ == '__main__':
    ### Generate Benign Cluster
    benign_train_file_df, benign_test_file_df = PayloadModel.generate_payload_cluster(DATA_TYPE.BENIGN)
    print(f"benign_test_file_df: {benign_test_file_df.shape}")
    # PayloadModel.generate_cluster_origins(benign_train_file_df, DATA_TYPE.BENIGN)
    ### Generate Malicious Cluster
    malicious_train_file_df, malicious_test_file_df = PayloadModel.generate_payload_cluster(DATA_TYPE.MALICIOUS)
    print(f"malicious_test_file_df: {malicious_test_file_df.shape}")
    # PayloadModel.generate_cluster_origins(malicious_train_file_df, DATA_TYPE.MALICIOUS)

    # PayloadModel.save_cluster_origins(PROCESSED_FILES_PATH+PAYLOAD_CLUSTER_ORIGINS_FILE_NAME, payload_cluster_origins)

    payload_cluster_origins = PayloadModel.read_cluster_origins(PROCESSED_FILES_PATH+PAYLOAD_CLUSTER_ORIGINS_FILE_NAME)
    print(payload_cluster_origins)
    # file_df = PayloadModel.get_test_set(benign_test_file_df, malicious_test_file_df)
    PayloadModel.test_accuracy(malicious_test_file_df)

