import json
import pickle
import shutil

def save_json(path, data):
    with open(path, 'w') as f:
        print(json.dumps(data), file = f)


def load_json(path, mode = 'r', encoding = 'utf-8'):
    with open(path, mode, encoding = encoding) as f:
        return json.load(f)
    

def save_pickle(path, data):
    with open(path, 'wb') as f:
        pickle.dump(data, f)


def load_pickle(file_path):
    with open(file_path, 'rb') as f:
        data = pickle.load(f)
        return data


def save_text(path, data, mode = 'w'):
    with open(path, mode) as f:
        if isinstance(data, dict):
            if isinstance(list(data.values())[0], (set, list)):
                for k, v in data.items():
                    print(k, file = f)
                    for item in v:
                        print(item, file = f)
            else:    
                for k, v in data.items():
                    print(k, '\n', v, file = f, end = '_' * 80 + '\n')
        elif isinstance(data, (set, list)):
            for i in data:
                print(i, file = f)
        else:
            print(data, file = f)


def copy_file(src_file, dest_file):
    shutil.copy(src_file, dest_file)


def load_file(path, mode = 'r'):
    with open(path, mode, encoding = 'utf-8', errors = 'ignore') as f:
        return f.read()