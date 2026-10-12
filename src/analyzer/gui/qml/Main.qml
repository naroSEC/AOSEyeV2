import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

ApplicationWindow {
    id: root
    width: 1480; height: 920; minimumWidth: 1080; minimumHeight: 700
    visible: true
    title: "AOSEye · Android Security Analysis"
    color: "#10141d"
    palette.window: "#10141d"; palette.windowText: "#d7deeb"
    palette.base: "#161d29"; palette.text: "#d7deeb"
    palette.button: "#263248"; palette.buttonText: "#d7deeb"
    palette.highlight: "#4566db"; palette.highlightedText: "white"
    palette.placeholderText: "#8294af"
    font.family: "Segoe UI"; font.pixelSize: 13
    property string sectionName: workspace.sectionName
    property string activeTab: workspace.currentTab
    property bool graphVisible: false
    function severityColor(value) {
        return value === "CRITICAL" ? "#f16c91" : value === "HIGH" ? "#f49a78" : value === "MEDIUM" ? "#e2c477" : "#83a9e9"
    }
    component Action: Button {
        hoverEnabled: true
        background: Rectangle {
            radius: 6
            color: parent.down ? "#40517a" : parent.hovered ? "#303e59" : "#222d40"
            border.color: "#34425a"
            Behavior on color { ColorAnimation { duration: 100 } }
        }
    }
    FileDialog { id: apkDialog; title: "Analyze Android application"; nameFilters: ["Android files (*.apk *.dex)"]; onAccepted: workspace.analyze(selectedFile.toString()) }
    FileDialog { id: projectDialog; title: "Reopen analysis"; nameFilters: ["AOSEye projects (*.json)"]; onAccepted: workspace.reopen(selectedFile.toString()) }
    FileDialog { id: saveDialog; title: "Save project / JSON report"; fileMode: FileDialog.SaveFile; defaultSuffix: "json"; onAccepted: workspace.save(selectedFile.toString()) }
    FileDialog { id: htmlReportDialog; title: "Export HTML (new file only)"; fileMode: FileDialog.SaveFile; defaultSuffix: "html"; onAccepted: workspace.exportReport(selectedFile.toString(), "html") }
    FileDialog { id: csvReportDialog; title: "Export CSV (new file only)"; fileMode: FileDialog.SaveFile; defaultSuffix: "csv"; onAccepted: workspace.exportReport(selectedFile.toString(), "csv") }
    FileDialog { id: irReportDialog; title: "Export normalized DEX IR (new file only)"; fileMode: FileDialog.SaveFile; defaultSuffix: "json"; onAccepted: workspace.exportReport(selectedFile.toString(), "ir-json") }
    Connections { target: workspace; function onCandidateReady() { candidateDialog.open() } function onCandidateAccepted() { candidateDialog.close() } }
    FileDialog { id: candidateSaveDialog; title: "Export separate candidate (new file only)"; fileMode: FileDialog.SaveFile; defaultSuffix: "candidate.json"; nameFilters: ["AOSEye candidate (*.candidate.json)"]; onAccepted: workspace.exportCandidate(selectedFile.toString()) }
    FileDialog { id: candidateOpenDialog; title: "Open unsigned candidate (read-only)"; nameFilters: ["AOSEye candidate (*.candidate.json)"]; onAccepted: workspace.reopenCandidate(selectedFile.toString()) }
    Dialog {
        id: candidateDialog; objectName: "candidateDialog"; title: "Read-only JEB candidate · separate from analysis"
        anchors.centerIn: parent; width: Math.min(950, root.width - 60); height: root.height - 100
        modal: true; standardButtons: Dialog.Close
        onClosed: { if (workspace.busy) workspace.cancel(); workspace.discardCandidate() }
        contentItem: ColumnLayout {
            RowLayout {
                Action { objectName: "exportCandidate"; text: "Export separate candidate…"; enabled: !workspace.busy && workspace.candidateText.length > 0; onClicked: candidateSaveDialog.open() }
                Action { objectName: "analyzeCandidate"; text: "Reverify & analyze expanded scope"; enabled: !workspace.busy && workspace.candidateText.length > 0; onClicked: workspace.analyzeCandidate() }
                Action { text: "Cancel"; enabled: workspace.busy; onClicked: workspace.cancel() }
            }
            Label { text: workspace.stage; Layout.fillWidth: true; wrapMode: Text.Wrap; textFormat: Text.PlainText }
            ScrollView {
                Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                TextArea { objectName: "candidateContent"; text: workspace.candidateText; readOnly: true; selectByMouse: true; textFormat: TextEdit.PlainText; wrapMode: TextEdit.WrapAnywhere; font.family: "Consolas" }
            }
        }
    }
    Dialog {
        id: settingsDialog; objectName: "backendSettings"; title: "Backend settings"; anchors.centerIn: parent; width: 650; modal: true
        standardButtons: Dialog.Close
        onOpened: indexPolicy.currentIndex = workspace.indexOrder === "manifest-first" ? 1 : 0
        contentItem: ScrollView {
          id: settingsScroll; objectName: "settingsScroll"
          implicitHeight: Math.min(settingsColumn.implicitHeight, root.height - 160)
          contentHeight: settingsColumn.implicitHeight
          contentWidth: availableWidth
          clip: true
          ColumnLayout {
            id: settingsColumn; width: settingsScroll.availableWidth; spacing: 16
            Label { text: "Use your installed JEB · Java 21"; font.pixelSize: 18 }
            TextField { id: jebPath; Layout.fillWidth: true; text: workspace.jebPath; placeholderText: "JEB installation directory" }
            Label { text: workspace.backendStatus; wrapMode: Text.Wrap; Layout.fillWidth: true }
            Label { text: "A connection probe does not certify DEX, CFG or decompiler execution.\nCapabilities are verified by actual operations."; color: "#9aabc5" }
            Action { text: "Save & check connection"; enabled: !workspace.busy; onClicked: { workspace.probe(jebPath.text); settingsDialog.close() } }
            Label { text: "Optional aapt2 · raw resource name lookup"; font.pixelSize: 16 }
            TextField { id: aapt2Path; objectName: "aapt2Path"; Layout.fillWidth: true; text: workspace.aapt2Path; placeholderText: "Absolute trusted aapt2 executable path; empty disables" }
            Label { text: "Uses a local executable on new analyses only. Saved evidence is unchanged."; wrapMode: Text.Wrap; Layout.fillWidth: true; color: "#9aabc5" }
            Action { objectName: "saveAapt2"; text: "Save aapt2 setting"; enabled: !workspace.busy; onClicked: { if (workspace.saveAapt2(aapt2Path.text)) settingsDialog.close() } }
            Label { text: workspace.stage; wrapMode: Text.Wrap; Layout.fillWidth: true; color: "#9aabc5" }
            RowLayout {
                Label { text: "JEB heap (MiB)" }
                SpinBox { id: heapBudget; objectName: "jvmHeapMiB"; from: 512; to: 16384; stepSize: 256; value: workspace.jvmHeapMiB; editable: true }
                Action { objectName: "saveJvmHeap"; text: "Save heap limit"; enabled: !workspace.busy; onClicked: { if (workspace.saveJvmHeap(heapBudget.value)) settingsDialog.close() } }
            }
            Label { text: "Heap is not total memory. A change restarts JEB on the next request."; wrapMode: Text.Wrap; Layout.fillWidth: true; color: "#9aabc5" }
            Label { text: "Index collection policy · new analyses only"; font.pixelSize: 16 }
            ComboBox {
                id: indexPolicy; objectName: "indexPolicy"; Layout.fillWidth: true
                model: ["native", "manifest-first"]; enabled: !workspace.busy
                currentIndex: workspace.indexOrder === "manifest-first" ? 1 : 0
            }
            Label { text: "native: JEB order. manifest-first: Manifest classes, then package hints.\nPriority spans JEB units per declaration kind. Budgets still apply.\nCallee bodies are not guaranteed. Hints do not prove ownership or entrypoints."; wrapMode: Text.Wrap; Layout.fillWidth: true; color: "#9aabc5" }
            Action { objectName: "saveIndexOrder"; text: "Save index policy"; enabled: !workspace.busy; onClicked: { if (workspace.saveIndexOrder(indexPolicy.currentText)) settingsDialog.close() } }
          }
        }
    }
    ColumnLayout {
        anchors.fill: parent; spacing: 0
        Label {
            objectName: "coverageBanner"; Layout.fillWidth: true; Layout.margins: 12
            visible: text.length > 0; text: workspace.coverageLabel
            textFormat: Text.PlainText; wrapMode: Text.Wrap; color: "#e2c477"
        }
        Rectangle {
            Layout.fillWidth: true; Layout.preferredHeight: 70; color: "#171f2d"
            RowLayout {
                anchors.fill: parent; anchors.margins: 18; spacing: 12
                Rectangle { width: 32; height: 32; radius: 9; color: "#6889ff"; Label { anchors.centerIn: parent; text: "A"; font.bold: true; font.pixelSize: 22; color: "#101725" } }
                Label { text: "AOSEye"; font.pixelSize: 23; font.bold: true }
                Label { text: " /  " + workspace.projectName; color: "#91a0b7"; Layout.fillWidth: true; elide: Text.ElideMiddle }
                Action { text: "Open APK / DEX"; enabled: !workspace.busy; onClicked: apkDialog.open() }
                Action { text: "Reopen"; enabled: !workspace.busy; onClicked: projectDialog.open() }
                Action { objectName: "openCandidate"; text: "Candidate"; enabled: !workspace.busy; onClicked: candidateOpenDialog.open() }
                Action {
                    text: "Save / Export"; enabled: !workspace.busy; onClicked: exportMenu.open()
                    Menu {
                        id: exportMenu
                        MenuItem { text: "Project JSON"; onTriggered: saveDialog.open() }
                        MenuItem { text: "HTML report"; onTriggered: htmlReportDialog.open() }
                        MenuItem { text: "CSV findings"; onTriggered: csvReportDialog.open() }
                        MenuItem { text: "Normalized DEX IR JSON"; onTriggered: irReportDialog.open() }
                    }
                }
                Action { text: "JEB settings"; enabled: !workspace.busy; onClicked: settingsDialog.open() }
            }
        }
        SplitView {
            Layout.fillWidth: true; Layout.fillHeight: true; orientation: Qt.Horizontal
            handle: Rectangle { implicitWidth: 1; color: "#303a4d" }
            Rectangle {
                SplitView.preferredWidth: 195; SplitView.minimumWidth: 160; color: "#141b26"
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 12; spacing: 5
                    Label { text: "WORKSPACE"; color: "#6e819e"; font.pixelSize: 11; font.letterSpacing: 2; Layout.topMargin: 12; Layout.bottomMargin: 18 }
                    Repeater {
                        model: ["Overview", "Manifest", "Network Policy", "Storage Policy", "Components", "Deep Links", "DEX", "Assets", "Findings", "Boundaries", "Diagnostics"]
                        delegate: ItemDelegate {
                            required property string modelData
                            Layout.fillWidth: true; text: modelData; height: 40
                            background: Rectangle { radius: 6; color: root.sectionName === modelData ? "#273754" : parent.hovered ? "#1d293d" : "transparent" }
                            enabled: !workspace.busy
                            onClicked: workspace.section(modelData)
                        }
                    }
                    Item { Layout.fillHeight: true }
                    Rectangle {
                        Layout.fillWidth: true; implicitHeight: 105; radius: 8; color: "#1c2739"
                        ColumnLayout {
                            anchors.fill: parent; anchors.margins: 12
                            Label { text: "LOCAL BACKEND"; color: "#7f96ba"; font.pixelSize: 10; font.letterSpacing: 1 }
                            Label { text: "JEB Core API"; font.bold: true }
                            Label { text: workspace.backendStatus; color: "#a8b8d0"; wrapMode: Text.Wrap; Layout.fillWidth: true; font.pixelSize: 11 }
                        }
                    }
                }
            }
            SplitView {
                SplitView.fillWidth: true; SplitView.minimumWidth: 450; orientation: Qt.Vertical
                handle: Rectangle { implicitHeight: 1; color: "#303a4d" }
                Rectangle {
                    color: "#101722"; SplitView.fillHeight: true
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 22; spacing: 15
                        RowLayout {
                            Label { text: root.sectionName + " / " + root.activeTab; color: "#889ab6"; Layout.fillWidth: true }
                            Action { text: "Back"; enabled: !workspace.busy && workspace.canGoBack; onClicked: workspace.goBack() }
                            Action { text: "Finding location"; enabled: !workspace.busy; onClicked: workspace.findingLocation() }
                            Action { text: "Decompile"; enabled: !workspace.busy; onClicked: workspace.decompile() }
                        }
                        Label { text: root.activeTab === "Network Policy" ? "Saved network policy" : workspace.detail.title || "Analysis workspace"; font.pixelSize: 22; font.bold: true; wrapMode: Text.Wrap; Layout.fillWidth: true }
                        RowLayout {
                            visible: root.sectionName === "Diagnostics"; Layout.fillWidth: true
                            ComboBox {
                                id: callTargetFilter; objectName: "callTargetFilter"; Layout.fillWidth: true
                                model: ["UNAVAILABLE", "ambiguous_units", "unknown_origin", "indexed_body_missing", "declared_no_code", "declaration_unknown", "unindexed_target", "missing_operand", "body_available", "ALL"]
                                enabled: !workspace.busy
                            }
                            Action { objectName: "queryCallTargets"; text: "Call sites"; enabled: !workspace.busy; onClicked: workspace.queryCallTargets(callTargetFilter.currentText, 0) }
                            Action { text: "Previous"; enabled: !workspace.busy && (workspace.callTargetPage.offset || 0) > 0; onClicked: workspace.queryCallTargets(workspace.callTargetPage.status, Math.max(0, workspace.callTargetPage.offset - 100)) }
                            Action { text: "Next"; enabled: !workspace.busy && !!workspace.callTargetPage.has_more; onClicked: workspace.queryCallTargets(workspace.callTargetPage.status, workspace.callTargetPage.offset + workspace.callTargetPage.shown) }
                        }
                        RowLayout {
                            visible: root.sectionName === "Diagnostics" && root.activeTab === "Bytecode"
                            Label { text: "Candidate limit (KiB)" }
                            SpinBox { id: candidateBudget; from: 1; to: 1024; value: 256; editable: true; enabled: !workspace.busy }
                            Action { objectName: "previewCallTarget"; text: "Preview target (JEB)"; enabled: !workspace.busy; onClicked: workspace.previewCallTarget(candidateBudget.value) }
                        }
                        Label {
                            visible: root.sectionName === "Diagnostics"; Layout.fillWidth: true; wrapMode: Text.Wrap
                            text: "Saved call sites only · caller links do not fetch missing bodies. " + (workspace.callTargetPage.total !== undefined ? "Filter: " + workspace.callTargetPage.status + " · " + workspace.callTargetPage.shown + " shown, offset " + workspace.callTargetPage.offset + " / " + workspace.callTargetPage.total + " saved matches" : "")
                            color: "#a8bddb"; textFormat: Text.PlainText
                        }
                        RowLayout {
                            visible: root.activeTab === "Network Policy"; Layout.fillWidth: true
                            TextField {
                                id: networkHost; objectName: "networkHost"; Layout.fillWidth: true
                                placeholderText: "Bare DNS host, e.g. api.example.com"; maximumLength: 253
                                enabled: !workspace.busy
                                onAccepted: workspace.queryNetworkHost(text)
                            }
                            Action { objectName: "queryNetworkHost"; text: "Check host"; enabled: !workspace.busy; onClicked: workspace.queryNetworkHost(networkHost.text) }
                            Action { text: "Saved policy"; enabled: !workspace.busy; onClicked: workspace.showNetworkPolicy() }
                        }
                        Label {
                            visible: root.activeTab === "Network Policy"; Layout.fillWidth: true
                            text: "Offline configuration lookup · no network access · default-only results do not cover other device configurations"
                            wrapMode: Text.Wrap; color: "#a8bddb"; textFormat: Text.PlainText
                        }
                        Label { visible: !!workspace.evidenceLocation.method && root.activeTab !== "Field XREF" && root.activeTab !== "Network Policy"; text: workspace.evidenceLocation.method || ""; Layout.fillWidth: true; elide: Text.ElideMiddle; color: "#a8bddb"; textFormat: Text.PlainText }
                        Label { visible: root.activeTab === "Field XREF"; text: workspace.selectedField; Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; color: "#a8bddb"; textFormat: Text.PlainText }
                        RowLayout {
                            visible: !!workspace.detail.title && root.activeTab !== "Network Policy"; spacing: 14
                            Label { text: workspace.detail.severity || ""; color: root.severityColor(text); font.bold: true }
                            Label { text: workspace.detail.type || ""; color: "#9aabc5" }
                            Label { text: workspace.detail.confidence || ""; color: "#9aabc5" }
                            Label { text: workspace.detail.verification || ""; color: "#9aabc5" }
                            Label { text: workspace.detail.analysis_level || ""; color: "#81a2ff" }
                        }
                        Flow {
                            visible: root.activeTab !== "Network Policy"
                            Layout.fillWidth: true; spacing: 2
                            Repeater {
                                model: ["Evidence", "Review", "Code", "Bytecode", "XREF", "JEB XREF", "Field XREF", "AST", "CFG", "Call Graph", "Data Flow"]
                                delegate: Button {
                                    required property string modelData
                                    text: modelData; flat: true; font.pixelSize: 11
                                    palette.buttonText: root.activeTab === modelData ? "#99b2ff" : "#8e9bb2"
                                    enabled: !workspace.busy
                                    onClicked: workspace.showTab(modelData)
                                }
                            }
                        }
                        TextField { id: codeSearch; Layout.fillWidth: true; placeholderText: "Find in evidence / code · Enter for next match"; onAccepted: { let start = codeView.text.indexOf(text, codeView.selectionEnd); if (start < 0) start = codeView.text.indexOf(text); if (start >= 0) codeView.select(start, start + text.length) } }
                        RowLayout {
                            visible: root.activeTab === "Field XREF"; Layout.fillWidth: true
                            ComboBox {
                                model: ["ALL", "READ", "WRITE"]; enabled: !workspace.busy && !!workspace.selectedField
                                currentIndex: ["ALL", "READ", "WRITE"].indexOf(workspace.fieldFilter)
                                onActivated: { workspace.filterFieldReferences(currentText); currentIndex = Qt.binding(function() { return ["ALL", "READ", "WRITE"].indexOf(workspace.fieldFilter) }) }
                            }
                            Action { text: "Previous"; enabled: !workspace.busy && workspace.fieldHasPrevious; onClicked: workspace.previousFieldPage() }
                            Label { text: workspace.fieldPageLabel; Layout.fillWidth: true; color: "#a8bddb" }
                            Action { text: "Next"; enabled: !workspace.busy && workspace.fieldHasNext; onClicked: workspace.nextFieldPage() }
                        }
                        RowLayout {
                            visible: root.activeTab === "JEB XREF"; Layout.fillWidth: true
                            Action { text: "Previous page"; enabled: !workspace.busy && workspace.xrefHasPrevious; onClicked: workspace.previousXrefPage() }
                            Label { text: workspace.xrefPageLabel; Layout.fillWidth: true; color: "#a8bddb" }
                            Action { text: "Next page"; enabled: !workspace.busy && workspace.xrefHasNext; onClicked: workspace.nextXrefPage() }
                        }
                        Label {
                            Layout.fillWidth: true; visible: root.activeTab === "Review"
                            text: workspace.reviewSummary; textFormat: Text.PlainText
                            wrapMode: Text.Wrap; color: "#a8bddb"; font.pixelSize: 11
                        }
                        ListView {
                            Layout.fillWidth: true; Layout.preferredHeight: visible ? 100 : 0
                            objectName: "referenceList"
                            visible: count > 0; clip: true; model: workspace.navigationItems
                            ScrollBar.vertical: ScrollBar { }
                            delegate: ItemDelegate {
                                required property var modelData
                                width: ListView.view.width
                                text: modelData.label + " · " + modelData.method + " @ 0x" + modelData.offset.toString(16)
                                enabled: !workspace.busy
                                onClicked: workspace.navigateLocation(modelData.method, modelData.offset, modelData.unit || "")
                            }
                        }
                        ScrollView {
                            Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                            TextArea {
                                id: codeView; text: workspace.content; readOnly: true; selectByMouse: true
                                Component.onCompleted: workspace.highlight(textDocument)
                                font.family: "Consolas"; font.pixelSize: 13; color: "#c0d0e5"
                                wrapMode: TextEdit.WrapAnywhere
                                background: Rectangle { color: "#111a27"; radius: 8 }
                            }
                        }
                    }
                }
                Rectangle {
                    SplitView.preferredHeight: 205; SplitView.minimumHeight: 130; color: "#171f2c"
                    visible: root.activeTab !== "Network Policy" && (workspace.detail.attack_path || []).length > 0
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 18
                        RowLayout {
                            Label { text: "ATTACK PATH"; font.letterSpacing: 1.5; font.pixelSize: 11; color: "#8da5c8" }
                            Item { Layout.fillWidth: true }
                            Label { text: "DEX evidence · bounded static analysis"; color: "#647c9c"; font.pixelSize: 11 }
                        }
                        ListView {
                            Layout.fillWidth: true; Layout.fillHeight: true; clip: true; orientation: ListView.Horizontal; spacing: 10
                            model: workspace.detail.attack_path || []
                            delegate: Row {
                                required property var modelData
                                spacing: 10
                                Rectangle {
                                    width: 225; height: 105; radius: 8; color: "#22314a"; border.color: "#3e547a"
                                    Column {
                                        anchors.fill: parent; anchors.margins: 12; spacing: 7
                                        Label { width: parent.width; text: modelData.label; elide: Text.ElideRight; color: "#abc0ff" }
                                        Label { width: parent.width; text: modelData.method; wrapMode: Text.WrapAnywhere; maximumLineCount: 2; elide: Text.ElideRight; font.pixelSize: 11 }
                                        Label { text: "offset 0x" + modelData.offset.toString(16); color: "#718bb0"; font.pixelSize: 11 }
                                    }
                                    MouseArea { anchors.fill: parent; enabled: !workspace.busy; cursorShape: Qt.PointingHandCursor; onClicked: workspace.navigateLocation(modelData.method, modelData.offset, modelData.unit || "") }
                                }
                                Label { text: "→"; color: "#819bcd"; anchors.verticalCenter: parent.verticalCenter }
                            }
                            Label { visible: parent.count === 0; text: "Select a flow finding to inspect its external entry and sink."; color: "#7385a0"; anchors.centerIn: parent }
                        }
                    }
                }
            }
            Rectangle {
                SplitView.preferredWidth: 350; SplitView.minimumWidth: 280; color: "#161e2b"
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 16; spacing: 12
                    visible: root.sectionName === "DEX"
                    Label { text: "DEX inventory"; font.pixelSize: 18; font.bold: true }
                    Label { text: workspace.dexScope; Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; textFormat: Text.PlainText; color: "#a8bddb" }
                    Label { text: "Unit presence ≠ declaration · unknown origins retained"; Layout.fillWidth: true; wrapMode: Text.Wrap; font.pixelSize: 11; color: "#8295b4" }
                    RowLayout {
                        Repeater {
                            model: ["units", "packages", "classes"]
                            delegate: Action {
                                required property string modelData
                                text: modelData; enabled: !workspace.busy
                                onClicked: { dexSearch.clear(); workspace.dexBrowse(modelData) }
                            }
                        }
                    }
                    TextField { id: dexSearch; Layout.fillWidth: true; placeholderText: "Search · Enter to apply"; enabled: !workspace.busy; onAccepted: workspace.searchDex(text) }
                    RowLayout {
                        Action { text: "Classes"; enabled: !workspace.busy; onClicked: { dexSearch.clear(); workspace.dexClasses() } }
                        Action { text: "Previous"; enabled: !workspace.busy && workspace.dexHasPrevious; onClicked: workspace.previousDexPage() }
                        Action { text: "Next"; enabled: !workspace.busy && workspace.dexHasNext; onClicked: workspace.nextDexPage() }
                    }
                    Label { text: workspace.dexPageLabel + " saved matches"; color: "#a8bddb" }
                    Label { objectName: "dexEmptyNotice"; text: workspace.dexEmptyLabel; visible: text.length > 0; Layout.fillWidth: true; wrapMode: Text.Wrap; textFormat: Text.PlainText; color: "#e2c477" }
                    ListView {
                        Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                        model: workspace.dexItems
                        ScrollBar.vertical: ScrollBar { }
                        delegate: ItemDelegate {
                            required property int index
                            required property var modelData
                            width: ListView.view.width
                            enabled: !workspace.busy
                            contentItem: Label { text: modelData.kind + " · " + modelData.name + "\n" + (modelData.unit || "Unknown unit") + (modelData.duplicate ? " · multiple unit origins" : "") + (modelData.kind === "method" && !modelData.has_body ? " [no saved body]" : ""); textFormat: Text.PlainText; wrapMode: Text.WrapAnywhere; color: "#c0d0e5" }
                            onClicked: { dexSearch.clear(); workspace.openDexEntry(index) }
                        }
                    }
                }
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 16; spacing: 12
                    visible: root.sectionName !== "DEX"
                    RowLayout {
                        Label { text: "Findings"; font.pixelSize: 18; font.bold: true; Layout.fillWidth: true }
                        Label { text: workspace.findingCount; color: "#95aff8"; font.pixelSize: 20 }
                    }
                    TextField { Layout.fillWidth: true; placeholderText: "Search findings, methods…"; onTextChanged: workspace.search(text) }
                    ComboBox { Layout.fillWidth: true; model: ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]; onActivated: workspace.filterSeverity(currentText) }
                    ListView {
                        id: findingList; Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 8
                        model: findingsModel
                        delegate: Rectangle {
                            required property int index
                            required property string title
                            required property string severity
                            required property string category
                            required property string analysis_level
                            required property string verification
                            width: findingList.width; height: 117; radius: 8
                            color: findingList.currentIndex === index ? "#273752" : hover.containsMouse ? "#233047" : "#1c283a"
                            border.color: findingList.currentIndex === index ? "#607fc7" : "#28364d"
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 12; spacing: 6
                                RowLayout {
                                    Label { text: severity; color: root.severityColor(severity); font.bold: true; font.pixelSize: 11 }
                                    Item { Layout.fillWidth: true }
                                    Label { text: analysis_level; color: "#849bc3"; font.pixelSize: 11 }
                                }
                                Label { text: title; Layout.fillWidth: true; wrapMode: Text.Wrap; maximumLineCount: 2; elide: Text.ElideRight; font.pixelSize: 12 }
                                Label { text: category + "  ·  " + verification; color: "#8295b4"; font.pixelSize: 10 }
                            }
                            MouseArea { id: hover; anchors.fill: parent; enabled: !workspace.busy; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: { findingList.currentIndex = index; workspace.selectFinding(index) } }
                        }
                    }
                    TextArea { Layout.fillWidth: true; Layout.preferredHeight: 70; text: workspace.analystNote; placeholderText: "Analyst note for selected finding"; wrapMode: TextEdit.Wrap; onTextChanged: if (activeFocus) workspace.note(text) }
                }
            }
        }
        Rectangle {
            Layout.fillWidth: true; Layout.preferredHeight: 42; color: "#1b2639"
            RowLayout {
                anchors.fill: parent; anchors.leftMargin: 16; anchors.rightMargin: 16; spacing: 16
                Label { text: workspace.stage; Layout.fillWidth: true; elide: Text.ElideRight; font.pixelSize: 11; color: "#a9bada" }
                ProgressBar { visible: workspace.busy; value: workspace.progress / 100; Layout.preferredWidth: 160 }
                Action { text: "Cancel"; visible: workspace.busy; onClicked: workspace.cancel() }
                Label { text: "LOCAL · v0.1"; color: "#6682ad"; font.pixelSize: 10 }
            }
        }
    }
}
