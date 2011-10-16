# Copyright (c) 2011, Edd Barrett <vext01@gmail.com>
# 
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Module for working with playlist items in HGD
"""

__author__ =  "Edd Barrett"

class PlaylistItem(object):
    """ Wrapper for a track in the playlist, whose items are read-only """

    def __init__(self, info):
        self.__info = info
    
    def get_tid(self):
        """ Return the track's track id as an integer. """
        return self.__info["tid"]

    def get_filename(self):
        """ Return the track's filename. """
        return self.__info["filename"]

    def get_tag_artist(self):
        """ Return artist metadata extracted by taglib. """
        return self.__info["tag_artist"]

    def get_tag_title(self):
        """ Return title metadata extracted by taglib. """
        return self.__info["tag_title"]

    def get_user(self):
        """ Return the name of the user who queued this track. """
        return self.__info["user"]



    def get_album(self):
        """ Return album metadata extracted by taglib """
        return self.__info["album"]

    def get_genre(self):
        """ Return genre metadata extracted by taglib """
        return self.__info["genre"]

    def get_duration(self):
        """ Return duration metadata extracted by taglib """
        return self.__info["duration"]

    def get_bitrate(self):
        """ Return bitrate metadata extracted by taglib """
        return self.__info["bitrate"]

    def get_samplerate(self):
        """ Return samplerate metadata extracted by taglib """
        return self.__info["samplerate"]

    def get_channels(self):
        """ Return channels metadata extracted by taglib """
        return self.__info["channels"]

    def get_year(self):
        """ Return year metadata extracted by taglib """
        return self.__info["year"]

    def __ro_set(self, val):
        raise AttributeError("attribute is read-only")

    tid = property(get_tid, __ro_set)
    filename = property(get_filename, __ro_set)
    tag_artist = property(get_tag_artist, __ro_set)
    tag_title = property(get_tag_title, __ro_set)
    user = property(get_user, __ro_set)
    album = property(get_album, __ro_set)
    genre = property(get_genre, __ro_set)
    duration = property(get_duration, __ro_set)
    bitrate = property(get_bitrate, __ro_set)
    samplerate = property(get_samplerate, __ro_set)
    channels = property(get_channels, __ro_set)
    year = property(get_year, __ro_set)

    def __str__(self):
        return ("Hgd.PlayListItem: "
                "tid=%d, filename='%s', tag_artist='%s', tag_title='%s', "
                "user='%s', album='%s', genre='%s', duration=%d, "
                "bitrate=%d, samplerate=%d, channels=%d, year=%d" %
                (self.tid, self.filename, self.tag_artist, self.tag_title,
                    self.user, self.album, self.genre, self.duration,
                    self.bitrate, self.samplerate, self.channels, self.year))

# quick test
if (__name__ == "__main__"):
    info = { "tid" : 4,
            "filename" : "test.ogg",
            "tag_artist" : "gunther",
            "tag_title" : "tralala",
            "user" : "edd",
            "album" : "pleasureman",
            "genre" : "europop",
            "duration" : 123,
            "bitrate" : 128,
            "samplerate" : 44100,
            "channels" : 1,
            "year" : 1968 }
    track = PlaylistItem(info)
    print(track)
