#include <stdio.h>
#include <curl/curl.h>
#include <windows.h>
#include <Lmcons.h>


int main(void)
{
    CURL *curl;
    FILE *fp;
    CURLcode res;
    /* Retrieve username windows*/
    char username[UNLEN+1];
    DWORD username_len = UNLEN+1;
    GetUserName(username, &username_len);

    char *location = "C:\test";
    char *url = "http://www.stackoverflow.com";
    char outfilename[FILENAME_MAX] = "page.html";
    curl = curl_easy_init();
    if (curl)
    {
        fp = fopen(outfilename,"wb");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);
    }

    /*Change execution policy powershell*/
    /*system("start powershell.exe Set-ExecutionPolicy RemoteSigned \n");
    system("start powershell.exe d:\\callPowerShell.ps1");
    system("cls");*/
    

    return 0;
}
