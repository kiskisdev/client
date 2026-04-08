msg = update

wip: 
	make update msg="WIP"

update:
	git add .
	git commit -m "$(msg)"
	git push origin main

tag:
	git tag withCreateeWorkouts
	git push origin --tags
