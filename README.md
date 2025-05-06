# Template - Plugin

<br>

<div align="center">
    <img src="https://user-images.githubusercontent.com/124595411/233356880-fdc7ea8a-8b1d-4991-8726-67b47e91df9e.svg" width="400px" />
</div>

<br>

## Purpose

Hello World plugin for Golang. 


## Configuration
Adapt the ```config.json```file by giving a name to your plugin.
```js
{
    "name": "template-plugin", // change the name here
    "version": "v0.0.0",
    "image_name": "ceherzog/plugin-template-plugin", // change the name here with codeclarity/plugin- before your name
    "image_version": "0.0.0",
    "depends_on": [],
    "description": "A CodeClarity plugin",
    "config": {
        "aConfigAttribute" : {
            "name": "Name",
            "type": "Array<string>",
            "description": "Description of the attribute",
            "required": true
        }
    }
}
```
