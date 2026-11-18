const response = await fetch(process.argv[2]);
console.log(await response.text());
