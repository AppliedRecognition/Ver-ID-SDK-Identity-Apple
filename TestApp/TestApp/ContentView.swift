//
//  ContentView.swift
//  TestApp
//
//  Created by Jakub Dolejs on 11/01/2024.
//  Copyright © 2024 Applied Recognition. All rights reserved.
//

import SwiftUI
import Security
import VerIDSDKIdentity

struct ContentView: View {
    
    @State var navigationPath = NavigationPath()
    @StateObject var testRunner: TestRunner = TestRunner()
    let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.timeStyle = .short
        formatter.dateStyle = .short
        return formatter
    }()
    
    var body: some View {
        NavigationStack(path: self.$navigationPath) {
            List {
                ForEach(self.testRunner.testResults) { testResult in
                    HStack {
                        Text(testResult.spec.id)
                        Spacer()
                        Button {
                            self.navigationPath.append(testResult)
                        } label: {
                            if testResult.passed {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.white, .green)
                            } else {
                                Image(systemName: "x.circle.fill")
                                    .foregroundStyle(.white, .red)
                            }
                        }
                    }
                }
                if let running = self.testRunner.runningTestName {
                    HStack {
                        Text(running)
                        Spacer()
                        ProgressView()
                    }
                }
            }
            .navigationTitle("Tests")
            .navigationDestination(for: TestResult.self) { testResult in
                VStack {
                    Group {
                        HStack {
                            if testResult.passed {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.white, .green)
                                Text("Test passed on \(self.dateFormatter.string(from: testResult.date))")
                            } else {
                                Image(systemName: "x.circle.fill")
                                    .foregroundStyle(.white, .red)
                                Text("Test failed on \(self.dateFormatter.string(from: testResult.date))")
                            }
                            Spacer()
                        }
                        if let comments = testResult.comments {
                            HStack {
                                Text(comments)
                                Spacer()
                            }
                        }
                    }
                    .padding(.bottom, 12)
                    HStack {
                        Text(testResult.spec.description)
                        Spacer()
                    }
                    Spacer()
                }
                .padding()
                .navigationTitle(testResult.spec.id)
                .navigationBarTitleDisplayMode(.inline)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task {
                            await self.testRunner.runTests()
                        }
                    } label: {
                        Image(systemName: "play.fill")
                    }
                    .disabled(self.testRunner.runningTestName != nil)
                }
            }
        }
    }
}

extension String: LocalizedError {
    public var errorDescription: String? { return self }
}
