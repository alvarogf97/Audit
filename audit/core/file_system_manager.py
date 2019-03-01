import os
import ntpath
import shutil
from hurry.filesize import size, alternative


class FileSystemManager:

    def __init__(self):
        pass

    @staticmethod
    def onerror(func, path, exc_info):
        import stat
        if not os.access(path, os.W_OK):
            os.chmod(path, stat.S_IWUSR)
            func(path)
        else:
            raise IOError

    @staticmethod
    def delete_folder(directory):
        shutil.rmtree(directory, onerror=FileSystemManager.onerror)

    @staticmethod
    def count_dir_files(directory):
        return sum([len(files) for r, d, files in os.walk(directory)])

    @staticmethod
    def path_leaf(path):
        head, tail = ntpath.split(path)
        return tail or ntpath.basename(head)

    @staticmethod
    def base_path(path):
        return ntpath.dirname(path)

    @staticmethod
    def get_file_size(file_path):
        return size(ntpath.getsize(file_path), system=alternative)

    @staticmethod
    def get_directory_content(path):
        result = dict()
        result["status"] = True
        parent_path = os.path.dirname(path)
        directories = [FileSystemDocument(FileSystemManager.path_leaf(directory), directory, False)
                       for directory in
                       [os.path.join(path, o) for o in os.listdir(path) if
                        os.path.isdir(os.path.join(path, o))]]
        files = [FileSystemDocument(FileSystemManager.path_leaf(file), file, True)
                 for file in
                 [os.path.join(path, o) for o in os.listdir(path) if not
                  os.path.isdir(os.path.join(path, o))]]
        documents = [FileSystemDocument("...", parent_path, False)] + directories + files
        result["data"] = FileSystemDocument.list_to_json(documents)
        return result


class FileSystemDocument:

    def __init__(self, name, abs_path, is_file):
        self.name = name
        self.abs_path = abs_path
        self.is_file = is_file

    def to_json(self):
        result = dict()
        result["name"] = self.name
        result["abs_path"] = self.abs_path
        result["is_file"] = self.is_file
        return result

    @staticmethod
    def list_to_json(_list):
        result = []
        for document in _list:
            result.append(document.to_json())
        return result
