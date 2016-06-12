import React from 'react';


class MemoryLayout extends React.Component {

  constructor(){
    super()
    this._setHeight = this._setHeight.bind(this)
  }

  //set the proper dimensions for the canvas object based on the viewport dimension
  _setHeight(){
    var navbarHeight = document.getElementById('navbar').offsetHeight;
    var informationHeight = document.getElementById('information').offsetHeight;
    var sliderHeight = document.getElementById('slider').offsetHeight;

    this.canvas.width = window.innerWidth - 30;
    this.canvas.height = window.innerHeight - (navbarHeight + informationHeight + sliderHeight + 50);
  }

  //callback of reactjs called when th component mounting is finished
  componentDidMount() {

    this.canvas = document.getElementById('memoryLayoutCanvas'); 

    this._setHeight() 
    
    //window.addEventListener("resize",  this._setHeight);      
    /*
    console.log(height)
    this.context.beginPath();
    this.context.rect(0, 0, 300, height);
    this.context.fillStyle = 'yellow';
    this.context.fill();
    */
  
    var stage = new createjs.Stage("memoryLayoutCanvas");
    
    var circle = new createjs.Shape();
    circle.graphics.beginFill("DeepSkyBlue").drawCircle(0, 0, 100);
    circle.x = 430;
    circle.y = 130;
    stage.addChild(circle);

    var circle2 = new createjs.Shape();
    circle2.graphics.beginFill("red").drawCircle(0, 0, 150);
    circle2.x = 100;
    circle2.y = 100;
    stage.addChild(circle2);


    stage.update();
  }

  render () {

    return (
      <div>
        <canvas id="memoryLayoutCanvas"></canvas>
      </div>
    );
  }

}

export default MemoryLayout;