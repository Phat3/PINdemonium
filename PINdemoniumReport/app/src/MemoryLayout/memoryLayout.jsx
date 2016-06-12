import React from 'react';


class MemoryLayout extends React.Component {

  constructor(){
    super()
    this._setHeight = this._setHeight.bind(this)
    this._drawMemory = this._drawMemory.bind(this)
    this._drawDump = this._drawDump.bind(this)
    this._drawArrow = this._drawArrow.bind(this)
  }

  //set the proper dimensions for the canvas object based on the viewport dimension
  _setHeight(){
    var navbarHeight = document.getElementById('navbar').offsetHeight;
    var informationHeight = document.getElementById('information').offsetHeight;
    var sliderHeight = document.getElementById('slider').offsetHeight;

    this.canvas.width = window.innerWidth - 30;
    this.canvas.height = window.innerHeight - (navbarHeight + informationHeight + sliderHeight + 50);
  }

  _drawMemory(){
    // draw the rectangle representing the memory of the process
    var memorySpace = new createjs.Shape();
    memorySpace.width = this.canvas.width / 3
    memorySpace.height = this.canvas.height - 50 
    memorySpace.x = memorySpace.width
    memorySpace.y = 50
    memorySpace.graphics.beginFill("DeepSkyBlue").drawRect(0, 0, memorySpace.width, memorySpace.height);

    // draw the label above the rectangle representing the process
    var labelMemorySpace = new createjs.Text("Memory Layout", "30px Arial", "black");
    // center the label on the rectangle
    var labelMemorySpaceBounds = labelMemorySpace.getBounds()
    labelMemorySpace.x = memorySpace.width + ( (memorySpace.width - labelMemorySpaceBounds.width) / 2)

    // draw the addresses label on the right of the memory layout
    var labelMemoryFirstAddress = new createjs.Text("0x00", "20px Arial", "red");
    var labelMemoryLastAddress = new createjs.Text("0xff", "20px Arial", "red");
    var labelmemoryAddressX = memorySpace.width * 2 + 10
    labelMemoryFirstAddress.x = labelmemoryAddressX
    labelMemoryFirstAddress.y = 50
    labelMemoryLastAddress.x = labelmemoryAddressX
    labelMemoryLastAddress.y = memorySpace.height - (labelMemoryLastAddress.getBounds().height) + 50

    this.stage.addChild(memorySpace, labelMemorySpace, labelMemoryFirstAddress, labelMemoryLastAddress);
    // update the canvas
    this.stage.update();
  }


  _drawDump(){
    // draw the rectangle representing the memory of the process
    var dumpShape = new createjs.Shape()
    dumpShape.name = "prova"
    dumpShape.width = this.canvas.width / 2.5
    dumpShape.height = 100
    dumpShape.x = (this.canvas.width - dumpShape.width)/2
    dumpShape.y = 200
    dumpShape.graphics.beginFill("red").drawRect(0, 0, dumpShape.width, dumpShape.height);
    
    // draw the label above the rectangle representing the process
    var labelDumpShape = new createjs.Text("DUMP 1", "30px Arial", "white");
    // center the label on the rectangle
    var labelDumpShapeBounds = labelDumpShape.getBounds()
    labelDumpShape.x = dumpShape.x + ( (dumpShape.width - labelDumpShapeBounds.width) / 2)
    labelDumpShape.y = dumpShape.y + ( ( dumpShape.height - labelDumpShapeBounds.height) / 2)
    
    // draw the addresses label on the right of the memory layout
    var labelDumpShapeFirstAddress = new createjs.Text("0x00400040", "20px Arial", "blue");
    var labelDumpShapeLastAddress = new createjs.Text("0x00411040", "20px Arial", "blue");
    labelDumpShapeFirstAddress.x = dumpShape.width + dumpShape.x + 10
    labelDumpShapeFirstAddress.y = dumpShape.y
    labelDumpShapeLastAddress.x = dumpShape.width + dumpShape.x + 10
    labelDumpShapeLastAddress.y = dumpShape.y +   dumpShape.height - (labelDumpShapeLastAddress.getBounds().height)

    this.stage.addChild(dumpShape, labelDumpShape, labelDumpShapeFirstAddress, labelDumpShapeLastAddress);
    // update the canvas
    this.stage.update();
  }

  _drawArrow(){

    var drawingCanvas = new createjs.Shape();
    this.stage.addChild(drawingCanvas);

    drawingCanvas.graphics.setStrokeStyle(2).beginStroke(createjs.Graphics.getRGB(0, 0, 0)).moveTo(10, 10).lineTo(200,200);

    drawingCanvas.graphics.setStrokeStyle(2).beginStroke(createjs.Graphics.getRGB(0, 0, 0)).moveTo(200, 200).lineTo(200,300);


    var radian = Math.atan2((110 - 240), (90 - 90))


    var arrow = new createjs.Shape();
    arrow.graphics.beginStroke(createjs.Graphics.getRGB(0, 0, 0)).moveTo(-5, +5).lineTo(0, 0).lineTo(-5, -5);
    
    var degree = radian / Math.PI * 180;
    arrow.x = 100;
    arrow.y = 100;
    arrow.rotation = degree;

    this.stage.addChild(arrow);
    this.stage.update();

  }

  //callback of reactjs called when th component mounting is finished
  componentDidMount() {
    this.canvas = document.getElementById('memoryLayoutCanvas'); 
    this._setHeight() 
    this.stage = new createjs.Stage("memoryLayoutCanvas");
    this._drawMemory()
    this._drawDump()
    this._drawArrow()
    //var prev_dump = this.stage.getChildByName("prova")
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