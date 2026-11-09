set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/forms")
set(CMAKE_AUTORCC ON)

set(QT_FORMS_UI
  forms/addressbookpage.ui
  forms/askpassphrasedialog.ui
  forms/coincontroldialog.ui
  forms/createwalletdialog.ui
  forms/editaddressdialog.ui
  forms/information.ui
  forms/intro.ui
  forms/modaloverlay.ui
  forms/optionsdialog.ui
  forms/overviewpage.ui
  forms/receivecoinsdialog.ui
  forms/receiverequestdialog.ui
  forms/sendcoinsdialog.ui
  forms/sendcoinsentry.ui
  forms/transactiondescdialog.ui
)

set(QT_SOURCES
  ${CMAKE_SOURCE_DIR}/src/init/bitcoin-qt.cpp

  addressbookpage.cpp
  addressbookpage.h

  addresstablemodel.cpp
  addresstablemodel.h

  askpassphrasedialog.cpp
  askpassphrasedialog.h

  bitcoin.cpp
  bitcoin.h

  bitcoin.qrc

  bitcoinaddressvalidator.cpp
  bitcoinaddressvalidator.h

   bitcoinamountfield.cpp
  bitcoinamountfield.h

  bitcoingui.cpp
  bitcoingui.h

  bitcoinunits.cpp
  bitcoinunits.h

  clientmodel.cpp
  clientmodel.h

  coincontroldialog.cpp
  coincontroldialog.h

  coincontroltreewidget.cpp
  coincontroltreewidget.h

  createwalletdialog.cpp
  createwalletdialog.h

  csvmodelwriter.cpp
  csvmodelwriter.h

  editaddressdialog.cpp
  editaddressdialog.h

  guiconstants.h

  guiutil.cpp
  guiutil.h

  informationwindow.cpp
  informationwindow.h

  initexecutor.cpp
  initexecutor.h

  intro.cpp
  intro.h

  main.cpp

  mintingfilterproxy.cpp
  mintingfilterproxy.h

  mintingtablemodel.cpp
  mintingtablemodel.h

  mintingview.cpp
  mintingview.h

  modaloverlay.cpp
  modaloverlay.h

  networkstyle.cpp
  networkstyle.h

  notificator.cpp
  notificator.h

  optionsdialog.cpp
  optionsdialog.h

  optionsmodel.cpp
  optionsmodel.h

  overviewpage.cpp
  overviewpage.h

  platformstyle.cpp
  platformstyle.h

  qrimagewidget.cpp
  qrimagewidget.h

  qvalidatedlineedit.cpp
  qvalidatedlineedit.h

  qvaluecombobox.cpp
  qvaluecombobox.h

  receivecoinsdialog.cpp
  receivecoinsdialog.h

  receiverequestdialog.cpp
  receiverequestdialog.h

  recentrequeststablemodel.cpp
  recentrequeststablemodel.h

  sendcoinsdialog.cpp
  sendcoinsdialog.h

  sendcoinsentry.cpp
  sendcoinsentry.h

  splashscreen.cpp
  splashscreen.h

  transactiondesc.cpp
  transactiondesc.h

  transactiondescdialog.cpp
  transactiondescdialog.h

  transactionfilterproxy.cpp
  transactionfilterproxy.h

  transactionoverviewwidget.cpp
  transactionoverviewwidget.h

  transactionrecord.cpp
  transactionrecord.h

  transactiontablemodel.cpp
  transactiontablemodel.h

  transactionview.cpp
  transactionview.h

  utilitydialog.cpp
  utilitydialog.h

  walletcontroller.cpp
  walletcontroller.h

  walletframe.cpp
  walletframe.h

  walletmodel.cpp
  walletmodel.h

  walletmodeltransaction.cpp
  walletmodeltransaction.h

  walletview.h
  walletview.cpp
)

add_executable(repeer-qt ${QT_FORMS_UI} ${QT_SOURCES})
target_link_libraries(repeer-qt PRIVATE
  bitcoin_node
  bitcoin_common
  bitcoin_util
  bitcoin_consensus
  bitcoin_wallet
  leveldb
  Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network
  ${QRENCODE_LIBRARIES}
  univalue
  ${LIBBITCOIN_CRYPTO}
  ${SSL_LIBRARIES}
  ${CRYPTO_LIBRARIES}
)
