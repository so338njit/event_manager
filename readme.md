
  This assignemnt was challenging to say the least. It was a great introduction into the world of QA and the implementation of using github to work as a team and track versions and issues. In the beginning it was a little tedious having to build issues in github and create the branches to fix the problem, deploy it back to github and merge the new branch, then document the fixes and then pull the changes back to your local main branch. It's a long process but it makes sense, this is a comprehensive but rather small program. As the scale of programs grow, this strict process allows multiple teams to work together on massive projects without breaking the code and using peer review. That was something fascinating I learned.
  Also, this project was eye opening to the QA process. The first big issue I had to tackle after figuring out mailtrap enviromental variables and the token issue was adjusting the username variables. What I learned while doing this was as you fix one problem, you sometimes cause 2 more and it continues to snowball. Coding can get frustrating, I had to step away and get some sleep and reattack in the morning with a fresh set of eyes. I feel this is something that can happen in the real world. Overall, frustrating at times, I really enjoyed this assignment. It was a challenge and a great learning opportunity.  

Issues:
[token issue](https://github.com/so338njit/event_manager/pull/4/commits/2a445583e69198db4ddcb85e396fb8b42caa0e8f)
Pytest was failing token issues when initially run through docker. Pytest fixtures were added with token creation to pass the test. 

[user update issue](https://github.com/so338njit/event_manager/pull/8)
Pytest was failing for a mixture of naming conventions used throughout the code. Some areas has "full name" listed and other areas had "first name" and "last name" listed seperately. Running the pytest pointed to the incorrect code where it was corrected.

[conftest and userschemas issue](https://github.com/so338njit/event_manager/pull/10/commits/622100803a23126fb82a1999b574295ec86a2ad1)
The conftest and userschemas were mismatched. Updated user schemas and tests.

[Username Validation Issue](https://github.com/so338njit/event_manager/pull/12/commits/50f36a3ca1cab2305a667837fc2c0742c03108c6)
This issue was quite involved. Solved issues relating to username validation. added length constraints on username creation to 20. Also fixed bugs of fullname vs first name and last name causing issues with pytest. Added a username column to the database tables and revision in the alembic file to upgrade head. Made username an optional field. Where I ran into the largest issue is the addition of username to the program without it being a listed column in the table. After revising the alembic file I was having issues syncing it with the postgresdb and it kept driving issues. After thorough debugging and up and down builds of the database, I was finally able to get it work. 

[Upgraded passwork requirements Issue](https://github.com/so338njit/event_manager/pull/14/commits/609835ec1569f6a00dfe3deeb9b97b3cec563316)
This issue was also quite involved. I updated the user_schemas file to require a minimum length, upper case, lower case, and a special character. This had to be done by creating a Register_user class and raise valueerror if the password didnt meet the requirements. After this was complete, the securite.py file had to be updated to the latest hashing standards. Using passlib import with the combinatination of bcrypt allowed for the latest hashing tech also with the ability to update the hashing algorithims in the future without affecting the code.

![Screenshot 2025-04-24 at 2 49 06 PM](https://github.com/user-attachments/assets/883c6ed4-2a99-453a-acf6-f48e1d456e34)
![Screenshot 2025-04-24 at 2 11 17 PM](https://github.com/user-attachments/assets/68efd71f-b486-42a0-9af0-99605f8df896)
