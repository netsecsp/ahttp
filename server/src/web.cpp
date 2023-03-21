/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 05/01/2022
http://ahttp.sf.net

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
copyright notice, this list of conditions and the
following disclaimer.

* Redistributions in binary form must reproduce the
above copyright notice, this list of conditions
and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#include "stdafx.h"
#include "web.h"

#define INDEXHTML \
			"<html>" \
			"<head>" \
			"<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>" \
			"<title>%s</title>" \
			"<style type='text/css'>" \
			    ".ssfront {" \
				"font-size: 16px;" \
				"font-family: sans-serif;" \
				"color: #464646;" \
				"}" \
				"a:link {" \
				"color: #464646;" \
				"text-decoration: none;" \
				"}" \
				"a:visited {" \
				"color: #464646;" \
				"text-decoration: none;" \
				"}" \
				"a:hover {" \
				"color: #0864ab;" \
				"text-decoration: underline;" \
				"}" \
				"#Content-Left{" \
					"height:400px;" \
					"float:left;" \
				"}" \
			"</style>" \
			"</head>" \
			"<body>" \
				"<h2 align='Content-Left'>Copyright (c) netsecsp 2012-2032, All rights reserved.<br>Author: Shengqian Yang, China, netsecsp@hotmail.com, last updated "STRING_UPDATETIME"</h2>" \
				"<div id='Content-Left'>" \
				"<div align='left' class='ssfront'>%s</div>" \
				"<hr>" \
				"<table align='left' class='ssfront'><tr height=10></tr>%s</table></div>" \
			"</body>" \
			"</html>"

BEGIN_ASYN_MESSAGE_MAP(CWeb)
ON_IOMSG_NOTIFY(OnIomsgNotify)
END_ASYN_MESSAGE_MAP()
/////////////////////////////////////////////////////////////////////////////
HRESULT CWeb::OnIomsgNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation )
{
    uint32_t lErrorCode = NO_ERROR;
    lpAsynIoOperation->GetCompletedResult(&lErrorCode, 0, 0);

    switch(lAction)
    {
    case Io_recv:
    {
        if( lErrorCode != NO_ERROR )
        {
            printf("detect, error: %d\n", lErrorCode);
            return E_NOTIMPL;
        }

        FILE_NOTIFY_INFORMATION *info; lpAsynIoOperation->GetIoBuffer(0, 0, (BYTE**)&info);

        do
        {
            std::string file((char*)info->FileName, info->FileNameLength); 

            #ifdef _DEBUG
            printf("detect %u.%s is changed\n", info->FileNameLength, file.c_str());
            #endif

            std::string::size_type ipos = 1;
            do
            {
                ipos = file.find('\\', ipos);
                if( ipos == std::string::npos ) break;
                file[ipos] = '/';
            }while(1);

            file.insert(0, "/"); //保证带"/"
            ipos = file.rfind('/');

            switch(info->Action)
            {
                case FILE_ACTION_ADDED:
                case FILE_ACTION_MODIFIED:
                     if( strcmp(file.c_str() + ipos + 1, "index.html") == 0 ) break;
                case FILE_ACTION_RENAMED_NEW_NAME:
                case FILE_ACTION_REMOVED: //无法删除index.html
                     if( ipos )
                         CreateFilelist(file.substr(0, ipos), true);
                     else
                         CreateFilelist("/", true);
                     break;
            }

            if( info->NextEntryOffset == 0 )
                break;
            else
                info = (FILE_NOTIFY_INFORMATION *)((BYTE *)info + info->NextEntryOffset);
        }while(1);

        return m_spAsynFileWatcher->Commit(lpAsynIoOperation, CP_ACP);
    }
    }
    return E_NOTIMPL; //通知系统释放lpAsynIoOperation
}

bool CWeb::CreateFilelist(const std::string &name, bool bCheckSubtree)
{
    WIN32_FIND_DATA data;
    HANDLE handle = FindFirstFile((m_filepath + (name == "/" ? ("/*.*") : (name + "/*.*"))).c_str(), &data);
    if( handle == INVALID_HANDLE_VALUE ) return false;

    std::string dirs, trls, name_utf8, file_utf8;
    char tr[2048];

	asynsdk::Convert(CP_ACP, name.c_str(), name.size(), CP_UTF8, name_utf8);

    do
    {
        std::string file = data.cFileName;
        if( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
        {
            if( file ==  "." || file == ".." ) continue;
        }
        else
        {
            std::string::size_type ipos = file.find_last_of("\\/");
            if( ipos == std::string::npos ) ipos = 0;
            if( strcmp(file.c_str() + ipos, "index.html") == 0 ) continue;
        }

        asynsdk::Convert(CP_ACP, file.c_str(), file.size(), CP_UTF8, file_utf8);
        if( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
        {
            sprintf_s(tr, 2048, "<tr onmouseOver=\"this.style.color='#0864ab';\" onmouseout=\"this.style.color='#464646';\">"
                        "<td align='left' width=300><a href='%s/%s/index.html'>%s</a></td><td align='left' width=100>&lt;DIR&gt;</td><td width=4></td>"
                        "<td width=200></td>"
                        "</tr>", name_utf8 == "/" ? "" : name_utf8.c_str(), file_utf8.c_str(), file_utf8.c_str());
            dirs += tr;
            if( bCheckSubtree ) CreateFilelist(name == "/" ? (name + file) : (name + "/" + file), bCheckSubtree);
        }
        else
        {
            LARGE_INTEGER filesize; //filesize.QuadPart
            filesize.LowPart  = data.nFileSizeLow;
            filesize.HighPart = data.nFileSizeHigh;

            char size[32];
            if( filesize.QuadPart >= 1024 * 1024 * 1000 )
                sprintf_s(size, 32, "%.2fGB", filesize.QuadPart / 1024.0 / 1024.0 / 1024.0);
            else if( filesize.QuadPart >= 1024 * 1000 )
                sprintf_s(size, 32, "%.2fMB", filesize.QuadPart / 1024.0 / 1024.0);
            else if( filesize.QuadPart >= 1000 )
                sprintf_s(size, 32, "%.2fKB", filesize.LowPart / 1024.0);
            else
                sprintf_s(size, 32, "%dB", filesize.LowPart);

            SYSTEMTIME st; FileTimeToSystemTime(&data.ftLastWriteTime, &st);
            char time[32];
            sprintf_s(time, 32, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

            sprintf_s(tr, 2048, "<tr onmouseOver=\"this.style.color='#0864ab';\" onmouseout=\"this.style.color='#464646';\">"
                        "<td align='left' width=300><a href='%s/%s' title='file: %s'>%s</a></td><td align='right' width=100>%s</td><td width=4></td>"
                        "<td align='left' width=200>%s</td>"
                        "</tr>", name_utf8 == "/" ? "" : name_utf8.c_str(), file_utf8.c_str(), file_utf8.c_str(), file_utf8.c_str(), size, time);
            trls += tr;
        }
    }
    while(FindNextFile(handle, &data) != 0);

    FindClose(handle);

    FILE *fcb = 0; fopen_s(&fcb, (m_filepath + (name == "/" ? ("/index.html") : (name + "/index.html"))).c_str(), "w");
    if( fcb )
    {
        std::string path = "<a href='/index.html' title='/'><font color='#0864ab'>Home</font></a>";
        if( name != "/" )
        {
            std::string::size_type ipos = 1;
            do
            {
                std::string::size_type pos1 = name_utf8.find('/', ipos);
                if( pos1 == std::string::npos )
                {
                    path += " / " + name_utf8.substr(ipos);
                    break;
                }
                std::string p = name_utf8.substr(0, pos1);
                std::string n = name_utf8.substr(ipos, pos1 - ipos);
                path += " / <a href='" + p + "/index.html' title='" + p + "'><font color='#0864ab'>" + n + "</font></a>";
                ipos = pos1 + 1;
            }while(1);
        }
        fprintf(fcb, INDEXHTML, name_utf8 == "/" ? ("Home") : (("Home" + name_utf8).c_str()), path.c_str(), (dirs + trls).c_str());
        fclose(fcb);
    }
    return true;
}
