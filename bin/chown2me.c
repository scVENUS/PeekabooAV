/*
 *-----------------------------------------------------------------------------
 *
 * Peekaboo Extended Email Attachment Behavior Observation Owl
 *
 * chown2me.c
 *
 * Copyright (C) 2016-2018  science + computing ag
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *-----------------------------------------------------------------------------
 *
 *
 * Changes ownership of every directory entry within /tmp that starts with
 * "amavis-" to user and group of the user who runs this program.
 *
 * Deletion of files remains in sample.py since only it knows what to delete and
 * no arguments should be passed to this program for security reasons.
 *
 *
 * Compile with
 *
 *   make chown2me
 *
 * Run the following command as root to set capability to allow chown
 *
 *   sudo setcap cap_chown+ep chown2me
 *
 */


#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>


int main(){

  DIR    *d;
  struct dirent *dir;
  char*  path   = "/tmp/";
  char*  prefix = "amavis-";
  char   test[strlen(prefix)+1];
  int    uid    = getuid();
  int    gid    = getgid();


  FILE * logfile_fd = fopen("chown2me.log", "w+");
  if (logfile_fd == NULL)
  {
		perror("Unable to open / write to logfile");
		return 1;
  }

  fprintf(logfile_fd, "Changing to %i:%i\n", uid, gid);

  d = opendir(path);
  if (d) {
    while ((dir = readdir(d)) != NULL) {

      // copy prefix to test string
      strncpy(test, dir->d_name, strlen(prefix));

      // compare if prefix equals test
      if (strcmp(prefix, test) == 0) {
        char fullpath[strlen(path)+strlen(dir->d_name)+1];
        fullpath[0]='\0';
        strcat(fullpath,path);
        strcat(fullpath,dir->d_name);
        fprintf(logfile_fd, "chown for %s\n", fullpath);
        // change owner to 1000
        int res = lchown(fullpath, uid, gid);
        if (res != 0){
          perror("chown");
          return res;
        }
      }
    }
  closedir(d);
  fclose(logfile_fd);
  }
  else {
    perror("opendir");
    return 5;
  }

  return 0;
}
