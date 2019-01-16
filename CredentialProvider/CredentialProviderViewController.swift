//
//  CredentialProviderViewController.swift
//  CredentialProvider
//
//  Created by Joshua Rutschmann on 12.12.18.
//  Copyright © 2018 Self. All rights reserved.
//

import AuthenticationServices

@available(iOS 12.0, *)
class CredentialProviderViewController: ASCredentialProviderViewController, UITableViewDelegate {

    var passwordView:GroupViewControllerMod?
    
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        if serviceIdentifiers.count > 0 {
            var identifier = serviceIdentifiers[0].identifier
            if !identifier.hasPrefix("http://") && !identifier.hasPrefix("https://") {
                identifier = "http://" + identifier
            }

            self.passwordView?.searchController?.searchBar.text = URL(string: identifier)?.host ?? ""
            self.passwordView?.searchController?.isActive = true
        }
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        _ = loadDataBase("keepass.kdbx", completion: {
            document in
            
            var nsresults: NSMutableArray = NSMutableArray()
            DatabaseDocument.search(document.kdbTree.root, searchText: credentialIdentity.recordIdentifier, results: nsresults)
            let results = nsresults as NSArray as! [KdbEntry]
            
            if(results.count != 0){
                var entry = results.first!
                
                for result:KdbEntry in results {
                    if(result.username()?.elementsEqual(credentialIdentity.user) ?? false){
                        entry = result
                    }
                }
                
                let passwordCredential = ASPasswordCredential(user: entry.username(), password: entry.password())
                self.extensionContext.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
            }
        })

    }

    /*
     Implement this method if provideCredentialWithoutUserInteraction(for:) can fail with
     ASExtensionError.userInteractionRequired. In this case, the system may present your extension's
     UI and call this method. Show appropriate UI for authenticating the user then provide the password
     by completing the extension request with the associated ASPasswordCredential.

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
    }
    */

    override func viewDidLoad() {
        sync()
        self.openDatabaseDocument("keepass.kdbx", completion: {
            document in
            
            var credentials:[ASPasswordCredentialIdentity] = []
            
            var groups = document.kdbTree.root!.groups as! [KdbGroup]
            groups.append(document.kdbTree.root!)
            for group:KdbGroup in groups {
                for entry:KdbEntry in group.entries as! [KdbEntry] {
                    let identifier = ASCredentialServiceIdentifier(identifier: entry.url(), type: ASCredentialServiceIdentifier.IdentifierType.URL)
                    let identity = ASPasswordCredentialIdentity(serviceIdentifier: identifier, user: entry.username(), recordIdentifier: entry.url())
                    credentials.append(identity)
                }
            }
            ASCredentialIdentityStore.shared.removeAllCredentialIdentities({
                success, error in
                
                ASCredentialIdentityStore.shared.saveCredentialIdentities(credentials, completion: {
                    success, error in
                    if(success){
                        print("Successfully updated AutoFill Passwords")
                    }
                })
            })
            
            
            let storyboard = UIStoryboard(name: "MainInterface", bundle: nil)
            self.passwordView = (storyboard.instantiateViewController(withIdentifier: "GroupViewController") as! GroupViewControllerMod)
            
            self.passwordView?.context = self.extensionContext
            self.passwordView?.parentGroup = document.kdbTree.root
            self.passwordView?.title = URL(fileURLWithPath: (document.filename)!).lastPathComponent
            
            let navigationController = UINavigationController(rootViewController: self.passwordView!)
            self.passwordView?.navigationItem.leftBarButtonItem = UIBarButtonItem(barButtonSystemItem: .done, target: self, action: #selector(self.close))
            self.present(navigationController, animated: true, completion: nil)
        })
    }
    
    func sync() {
        let fileManager = FileManager.default        
        let extensionDocuments = fileManager.containerURL(forSecurityApplicationGroupIdentifier: "group.tech.rutschmann.MiniKeePass")!
        let databaseFileURL = extensionDocuments.appendingPathComponent("keepass.kdbx")
        let keyfileURL = extensionDocuments.appendingPathComponent("keepass.key")
        
        let databaseFileExtURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.appendingPathComponent("keepass.kdbx")
        let keyfileExtURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.appendingPathComponent("keepass.key")
        
        do {
            if fileManager.fileExists(atPath: databaseFileExtURL.path){
                try fileManager.removeItem(atPath: databaseFileExtURL.path)
            }
            try fileManager.copyItem(at: databaseFileURL, to: databaseFileExtURL)
            
            if fileManager.fileExists(atPath: keyfileExtURL.path){
                try fileManager.removeItem(atPath: keyfileExtURL.path)
            }
            try fileManager.copyItem(at: keyfileURL, to: keyfileExtURL)
        } catch {
            print("Error syncing")
        }
    }
    
    @objc func close(){
        self.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
    }
    
    func openDatabaseDocument(_ filename: String, completion: @escaping (_ result: DatabaseDocument) -> Void) {
        if !loadDataBase(filename, completion: completion) {
            // Prompt the user for a password
            let storyboard = UIStoryboard(name: "PasswordEntry", bundle: nil)
            let navigationController = storyboard.instantiateInitialViewController() as? UINavigationController
            
            let passwordEntryViewController = navigationController?.topViewController as? PasswordEntryViewController
            passwordEntryViewController?.donePressed = { passwordEntryViewController in
                self.openDatabase(with: passwordEntryViewController, filename: filename, completion: completion)
            }
            passwordEntryViewController?.cancelPressed = { passwordEntryViewController in
                passwordEntryViewController.dismiss(animated: true)
            }
            
            passwordEntryViewController?.filename = filename
            passwordEntryViewController?.keyFiles = DatabaseManager.sharedInstance()?.getKeyFiles() as? [String]
            
            self.present(navigationController!, animated: true, completion: nil)
        }
    }
    
    func loadDataBase(_ filename: String, completion: @escaping (_ result: DatabaseDocument) -> Void) -> Bool {
        let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        
        // Load the password and keyfile from the keychain
        let password = KeychainUtils.string(forKey: filename, andServiceName: KEYCHAIN_PASSWORDS_SERVICE)
        let keyFile = KeychainUtils.string(forKey: filename, andServiceName: KEYCHAIN_KEYFILES_SERVICE)
        
        // Try and load the database with the cached password from the keychain
        if password != nil || keyFile != nil {
            // Get the absolute path to the database
            let path = documentsURL.appendingPathComponent(filename).path
            
            // Get the absolute path to the keyfile
            var keyFilePath: String? = nil
            if keyFile != nil {
                keyFilePath = documentsURL.appendingPathComponent(keyFile!).path
            }
            
            // Load the database
            let dd = DatabaseDocument(filename: path, password: password, keyFile: keyFilePath)
            completion(dd!)
            // TODO catch objc errors
            return true
        }
        return false
    }
    
    func openDatabase(with passwordEntryViewController: PasswordEntryViewController?, filename:String, completion:@escaping (_ result:DatabaseDocument) -> Void) {
        
        let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        
        let path = documentsURL.appendingPathComponent(filename).path
        
        // Get the password
        var password = passwordEntryViewController?.password
        if (password == "") {
            password = nil
        }
        
        // Get the keyfile
        let keyFile = passwordEntryViewController?.keyFile
        var keyFilePath: String? = nil
        if keyFile != nil {
            keyFilePath = documentsURL.appendingPathComponent(keyFile!).path
            
            // Open the database
            // TODO catch objc errors
            let databasedocument = DatabaseDocument(filename: path, password: password, keyFile: keyFilePath)
            
            // Store the password in the keychain
            if AppSettings.sharedInstance().rememberPasswordsEnabled() {
                KeychainUtils.setString(password, forKey: filename, andServiceName: KEYCHAIN_PASSWORDS_SERVICE)
                KeychainUtils.setString(keyFile, forKey: filename, andServiceName: KEYCHAIN_KEYFILES_SERVICE)
            }
            
            passwordEntryViewController?.dismiss(animated: true) {
                completion(databasedocument!)
            }

        }
        
    }
}
