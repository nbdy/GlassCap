import os
import string

import nude


class Checker:
    def DirectoryChecker(self):
        if os.path.exists('./carved_content') is False:
            os.makedirs('./carved_content')
        if os.path.exists('./carved_content/pictures') is False:
            os.makedirs('./carved_content/pictures')
        if os.path.exists('./carved_content/pictures/nude') is False:
            os.makedirs('./carved_content/pictures/nude')
        if os.path.exists('./carved_content/pictures/other') is False:
            os.makedirs('./carved_content/pictures/other')
        if os.path.exists('./carved_content/archives') is False:
            os.makedirs('./carved_content/archives')
        if os.path.exists('./carved_content/urls') is False:
            os.makedirs('./carved_content/urls')
        if os.path.exists('./carved_content/exe') is False:
            os.makedirs('./carved_content/exe')
        if os.path.exists('./carved_content/pdf') is False:
            os.makedirs('./carved_content/pdf')

    def NudeChecker(self, args):
        nude_counter = 0
        other_counter = 0
        picture_path = './carved_content/pictures/'
        nude_path = './carved_content/pictures/nude/'
        pictures = []
        temp_pictures = [f for f in os.listdir(picture_path) if os.path.isfile(os.path.join(picture_path, f))]
        for temp_picture in temp_pictures:
            if temp_picture.endswith('.jpg') or temp_picture.endswith('.jpeg'):
                temp_picture = picture_path + temp_picture
                pictures.append(temp_picture)
        for picture in pictures:
            try:
                if nude.is_nude(picture) is True:
                    tmp_picture = string.split(picture, '/')[-1]
                    tmp_picture = nude_path + tmp_picture
                    os.rename(picture, tmp_picture)
                    nude_counter += 1
                else:
                    other_counter += 1
            except:
                pass
        return nude_counter, other_counter
