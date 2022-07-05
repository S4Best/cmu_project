XCOPY /y opencv\build\x64\vc15\bin\opencv_world455.dll x64\Release\opencv_world455.dll*
XCOPY /y opencv\build\x64\vc15\bin\opencv_world455d.dll x64\Debug\opencv_world455d.dll*
XCOPY /y opencv\build\x64\vc15\bin\opencv_videoio_ffmpeg455_64.dll x64\Release\opencv_videoio_ffmpeg455_64.dll*
XCOPY /y opencv\build\x64\vc15\bin\opencv_videoio_ffmpeg455_64.dll x64\Debug\opencv_videoio_ffmpeg455_64.dll*
XCOPY /y opencv\build\x64\vc15\bin\opencv_videoio_msmf455_64d.dll x64\Debug\opencv_videoio_msmf455_64d.dll*
XCOPY /y opencv\build\x64\vc15\bin\opencv_videoio_msmf455_64.dll x64\Release\opencv_videoio_msmf455_64.dll*
XCOPY /y db-18.1.40\libdb181.dll x64\Release\libdb181.dll*
XCOPY /y db-18.1.40\libdb181.dll x64\Debug\libdb181.dll*
xcopy /S /E /H /Y /I "rundata" "x64\Release"
xcopy /S /E /H /Y /I "rundata" "x64\Debug"
xcopy /y common\server-conf.json x64\release\server-conf.json*
xcopy /y common\client-conf.json x64\release\client-conf.json*
XCOPY /y common\windows_openssl_dll\libcrypto-1_1-x64.dll x64\Release\libcrypto-1_1-x64.dll*
XCOPY /y common\windows_openssl_dll\libcrypto-1_1-x64.dll x64\Debug\libcrypto-1_1-x64.dll*
XCOPY /y common\windows_openssl_dll\libssl-1_1-x64.dll x64\Release\libssl-1_1-x64.dll*
XCOPY /y common\windows_openssl_dll\libssl-1_1-x64.dll x64\Debug\libssl-1_1-x64.dll*
XCOPY /S /E /H /Y /I common\keys x64\Release\keys\*
XCOPY /S /E /H /Y /I common\keys x64\Debug\keys\*
XCOPY /S /E /H /Y /I common\db x64\Release\db\*
XCOPY /S /E /H /Y /I common\db x64\Debug\db\*
XCOPY /S /E /H /Y /I common\openssl x64\Release\openssl\*
XCOPY /S /E /H /Y /I common\openssl x64\Debug\openssl\*
xcopy /y lgofficer\officer_vehicle.jpg x64\release\officer_vehicle.jpg*