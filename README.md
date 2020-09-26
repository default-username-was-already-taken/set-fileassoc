# Set-FileAssoc.ps1 - a script to change Windows 10 file associations


## What?
This script allows a user or an IT administrator to change user file associations in Windows 10.

## Why?
User file associations in newer versions of Windows are normally protected from an unauthorized change, and therefore can only be set interactively through Settings app, or using a XML file pushed through GPO.

The XML method has several drawbacks:
- IT administrator has to keep track of any new associations when a Windows Feature Update gets released;
- if the computer is not in a domain, associations can only be set in a reference image, and as a result:
    - apps also have to be pre-built in your image;
    - once an user changes one of their file associations, it cannot be set back using the XML method.

A [SetUserFTA tool](https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user) has been made in 2017 to combat this limitation. However, it is also not a perfect solution:
- it only changes associations for the user that launched the tool;
- this is problematic if computers are managed by means of a remote configuration administration tool, like Ansible;
- workarounds to run SetUserFTA in different user contexts exist, but they are also not ideal;
- closed-source model.

For my personal use case (domainless network of Ansible-managed Windows 10 nodes with a "bleeding-edge" update policy), a different approach was needed, therefore, this script was made.

# How?
1. Download the script;
2. Specify mandatory parameters - file extension and a ProgID (extension handler):
    - `-Extension .pdf -ProgID SumatraPDF`
    - `-Extension .html -ProgID ChromeHTML`
3. Set the user context in which this script should run:
    - current user only: `-CurrentUser`
    - all users: `-AllUsers`
    - specific users: `-Users user1, user2`
4. Run the script:
    - `.\Set-FileAssoc.ps1 -Extension .pdf -ProgID SumatraPDF -CurrentUser`
    - (shorthand version) `.\Set-FileAssoc.ps1 .pdf SumatraPDF`

## Is that... legal?
This script is a product of reverse-engineering Windows binaries. Therefore, if your organization has to strictly adhere to Microsoft EULA, it may be problematic, legal-wise, to use this script, because:
- it circumvents the measures set in place by Microsoft to prevent tampering with file associations and user experience;
- it uses features that were implemented by reverse-engineering binaries that are "legally protected" from being reverse-engineered.

Consult your legal department for guidance.

## Credits
Christoph Kolbicz for SetUserFTA: https://kolbi.cz

## License
See UNLICENSE file.
