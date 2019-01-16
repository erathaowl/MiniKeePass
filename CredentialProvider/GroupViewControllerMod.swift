//
//  GroupViewControllerMod.swift
//  CredentialProvider
//
//  Created by Joshua Rutschmann on 12.12.18.
//  Copyright © 2018 Self. All rights reserved.
//

import Foundation
import AuthenticationServices

class GroupViewControllerMod: GroupViewController {
    
    var context: ASCredentialProviderExtensionContext?
 
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let identifier:String = (tableView.cellForRow(at: indexPath)?.reuseIdentifier)!
        if  identifier == "EntryCell" {
            let entry = entries[indexPath.row]
            let passwordCredential = ASPasswordCredential(user: entry.username(), password: entry.password())
            self.context?.completeRequest(withSelectedCredential: passwordCredential, completionHandler: nil)
        }
    }
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        super.prepare(for: segue, sender: sender)
        
        if let destination = segue.destination as? GroupViewControllerMod {
            destination.context = self.context
        }
    }
}
