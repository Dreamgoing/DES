cmake_minimum_required(VERSION 3.7)
project(DES)

#set(CMAKE_INCLUDE_CURRENT_DIR ON)
#set(QT_HOME "/usr/local/Cellar/qt5/5.6.1-1/")
##打开QT的MOC功能和UI文件处理功能
#INCLUDE_DIRECTORIES(${QT_HOME}/include/QtCore)
#INCLUDE_DIRECTORIES(${QT_HOME}/include/QtWidgets)
#INCLUDE_DIRECTORIES(${QT_HOME}/include/QUiTools)
#
#set(CMAKE_INCLUDE_CURRENT_DIR on)
#set(CMAKE_PREFIX_PATH ${QT_HOME})
#set(CMAKE_AUTOMOC ON)
#set(CMAKE_AUTOUIC ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Debug)

#查找qt的库
#find_package( Qt5Core REQUIRED )
#find_package( Qt5Widgets REQUIRED )
#find_package( Qt5Gui REQUIRED )
#find_package( Qt5UiTools REQUIRED )

set(SOURCE_FILES test/main.cpp src/DES.hpp src/fileDES.hpp)
add_executable(DES ${SOURCE_FILES})
add_executable(qtDES ${SOURCE_FILES})
#
#target_link_libraries(DES Qt5::Widgets Qt5::UiTools Qt5::Core)