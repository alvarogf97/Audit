import os
import ntpath


class FileSystemManager:

    def __init__(self):
        pass

    @staticmethod
    def delete_folder(directory):
        if not os.path.isdir(directory):
            os.remove(directory)
        else:
            for item in os.listdir(directory):
                FileSystemManager.delete_folder((directory + '/' + item) if directory != '/' else '/' + item)
                os.rmdir(item)
        os.rmdir(directory)

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
        return ntpath.getsize(file_path)
