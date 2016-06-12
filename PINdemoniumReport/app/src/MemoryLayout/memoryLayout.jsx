import React from 'react';


class MemoryLayout extends React.Component {

  constructor(){
    super()
    this._setHeight = this._setHeight.bind(this)
    this._drawMemory = this._drawMemory.bind(this)
    this._drawDump = this._drawDump.bind(this)
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
    var memorySpaceWidth = this.canvas.width / 3
    var memorySpaceHeight = this.canvas.height - 50 
    memorySpace.graphics.beginFill("DeepSkyBlue").drawRect(memorySpaceWidth, 50, memorySpaceWidth, memorySpaceHeight);
    this.stage.addChild(memorySpace);

    // draw the label above the rectangle representing the process
    var labelMemorySpace = new createjs.Text("Memory Layout", "30px Arial", "black");
    // center the label on the rectangle
    var labelMemorySpaceBounds = labelMemorySpace.getBounds()
    labelMemorySpace.x = memorySpaceWidth + ( (memorySpaceWidth - labelMemorySpaceBounds.width) / 2)
    this.stage.addChild(labelMemorySpace);

    // draw the addresses label on the right of the memory layout
    var labelMemoryFirstAddress = new createjs.Text("0x00", "20px Arial", "red");
    var labelMemoryLastAddress = new createjs.Text("0xff", "20px Arial", "red");
    var labelmemoryAddressX = memorySpaceWidth * 2 + 10
    labelMemoryFirstAddress.x = labelmemoryAddressX
    labelMemoryFirstAddress.y = 50
    labelMemoryLastAddress.x = labelmemoryAddressX
    labelMemoryLastAddress.y = memorySpaceHeight - (labelMemoryLastAddress.getBounds().height) + 50
    this.stage.addChild(labelMemoryFirstAddress);
    this.stage.addChild(labelMemoryLastAddress);
    // update the canvas
    this.stage.update();
  }


  _drawDump(){
    // draw the rectangle representing the memory of the process
    var dumpShape = new createjs.Shape();
    var dumpShapeWidth = this.canvas.width / 2.5
    var dumpShapeHeight = 100
    var dumpShapeX = (this.canvas.width - dumpShapeWidth)/2
    var dumpShapeY = 300
    dumpShape.graphics.beginFill("red").drawRect(dumpShapeX, dumpShapeY, dumpShapeWidth, dumpShapeHeight);
    this.stage.addChild(dumpShape);
    
    // draw the label above the rectangle representing the process
    var labelDumpShape = new createjs.Text("DUMP 1", "30px Arial", "white");
    // center the label on the rectangle
    var labelDumpShapeBounds = labelDumpShape.getBounds()
    labelDumpShape.x = dumpShapeX + ( (dumpShapeWidth - labelDumpShapeBounds.width) / 2)
    labelDumpShape.y = dumpShapeY + ( (dumpShapeHeight - labelDumpShapeBounds.height) / 2)
    this.stage.addChild(labelDumpShape);
    
    // draw the addresses label on the right of the memory layout
    var labelDumpShapeFirstAddress = new createjs.Text("0x00400040", "20px Arial", "blue");
    var labelDumpShapeLastAddress = new createjs.Text("0x00411040", "20px Arial", "blue");
    labelDumpShapeFirstAddress.x = dumpShapeWidth + dumpShapeX + 10
    labelDumpShapeFirstAddress.y = dumpShapeY
    labelDumpShapeLastAddress.x = dumpShapeWidth + dumpShapeX + 10
    labelDumpShapeLastAddress.y = dumpShapeY +  dumpShapeHeight - (labelDumpShapeLastAddress.getBounds().height)
    this.stage.addChild(labelDumpShapeFirstAddress);
    this.stage.addChild(labelDumpShapeLastAddress);
    // update the canvas
    
    this.stage.update();
  }

  //callback of reactjs called when th component mounting is finished
  componentDidMount() {
    this.canvas = document.getElementById('memoryLayoutCanvas'); 
    this._setHeight() 
    this.stage = new createjs.Stage("memoryLayoutCanvas");
    this._drawMemory()
    this._drawDump()
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